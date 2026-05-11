// Copyright 2026 The Lattice Authors, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shim_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
	"github.com/alatticeio/lattice-shim/shim/internal/test"
)

// socks5Handshake performs the SOCKS5 greeting and request, returning a
// net.Conn ready for data relay on success.
func socks5Dial(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	// Greeting: version=5, nauth=1, method=0x00 (no auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("unexpected greeting: %x %x", greeting[0], greeting[1])
	}

	// Request: CONNECT to targetAddr.
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	ip := net.ParseIP(host)
	var req []byte
	if ip4 := ip.To4(); ip4 != nil {
		req = make([]byte, 6+4)
		req[3] = 0x01 // IPv4
		copy(req[4:8], ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = make([]byte, 6+16)
		req[3] = 0x04 // IPv6
		copy(req[4:20], ip6)
	} else {
		// Domain name.
		req = make([]byte, 7+len(host))
		req[3] = 0x03 // domain
		req[4] = byte(len(host))
		copy(req[5:], host)
	}

	req[0] = 0x05 // version
	req[1] = 0x01 // CONNECT
	req[2] = 0x00 // reserved
	binary.BigEndian.PutUint16(req[len(req)-2:], uint16(port))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read reply.
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if hdr[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("reply version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("reply code %d", hdr[1])
	}
	// Skip the bound address.
	switch hdr[3] {
	case 0x01: // IPv4
		var tail [6]byte
		io.ReadFull(conn, tail[:])
	case 0x04: // IPv6
		var tail [18]byte
		io.ReadFull(conn, tail[:])
	case 0x03: // domain
		var domLen [1]byte
		io.ReadFull(conn, domLen[:])
		tail := make([]byte, domLen[0]+2)
		io.ReadFull(conn, tail)
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported reply addr type %d", hdr[3])
	}

	return conn, nil
}

func TestSocks5_BasicRelay(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	// Listen on the netstack.
	ln, err := ns.ListenTCP("127.0.0.1:9080")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	msg := []byte("hello through socks5")
	resp := []byte("response from netstack")

	go func() {
		conn, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, rErr := conn.Read(buf)
		if rErr != nil {
			return
		}
		if string(buf[:n]) != string(msg) {
			t.Errorf("unexpected message: %q", buf[:n])
		}
		conn.Write(resp)
	}()

	// Start SOCKS5 server on host loopback.
	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	// Connect through SOCKS5.
	conn, err := socks5Dial(srv.Addr().String(), "127.0.0.1:9080")
	if err != nil {
		t.Fatalf("socks5Dial: %v", err)
	}

	if _, err := conn.Write(msg); err != nil {
		conn.Close()
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(resp) {
		conn.Close()
		t.Errorf("expected %q, got %q", resp, buf[:n])
	}

	conn.Close()
	srv.Close()
	wg.Wait()
}

func TestSocks5_PolicyAllow(t *testing.T) {
	policy := &test.MockPolicyChecker{}
	audit := &test.MockAuditWriter{}

	ns, err := shim.NewNetstack("127.0.0.1",
		shim.WithIdentity("socks5-client"),
		shim.WithPolicy(policy),
		shim.WithAudit(audit),
	)
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ln, err := ns.ListenTCP("127.0.0.1:9081")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 64)
			n, _ := conn.Read(buf)
			if n > 0 {
				conn.Write([]byte("ok"))
			}
		}
	}()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := socks5Dial(srv.Addr().String(), "127.0.0.1:9081")
	if err != nil {
		t.Fatalf("socks5Dial: %v", err)
	}

	conn.Write([]byte("hello"))
	buf := make([]byte, 64)
	conn.Read(buf)
	conn.Close()

	time.Sleep(50 * time.Millisecond)

	if audit.AllowedCount() != 1 {
		t.Errorf("expected 1 allow audit event, got %d", audit.AllowedCount())
	}

	call := policy.LastCall()
	if call == nil || call.Identity != "socks5-client" {
		t.Errorf("expected policy check for 'socks5-client', got %+v", call)
	}

	srv.Close()
	wg.Wait()
}

func TestSocks5_PolicyDeny(t *testing.T) {
	policy := &test.MockPolicyChecker{
		AllowFn: func(identity string, dstIP net.IP, dstPort uint16) bool {
			return false
		},
	}
	audit := &test.MockAuditWriter{}

	ns, err := shim.NewNetstack("10.100.0.1",
		shim.WithIdentity("socks5-client"),
		shim.WithPolicy(policy),
		shim.WithAudit(audit),
	)
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	// Policy denies everything, so the SOCKS5 reply should be an error.
	conn, err := socks5Dial(srv.Addr().String(), "10.0.0.1:443")
	if err == nil {
		conn.Close()
		t.Fatal("expected SOCKS5 error reply when policy denies")
	}

	time.Sleep(50 * time.Millisecond)

	if audit.DroppedCount() != 1 {
		t.Errorf("expected 1 drop event, got %d", audit.DroppedCount())
	}

	srv.Close()
	wg.Wait()
}

func TestSocks5_DomainName(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ln, err := ns.ListenTCP("127.0.0.1:9082")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 64)
			n, _ := conn.Read(buf)
			if n > 0 {
				conn.Write([]byte("domain-ok"))
			}
		}
	}()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	// Use a custom socks5 dial that sends a domain name address.
	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	// Greeting.
	conn.Write([]byte{0x05, 0x01, 0x00})
	var g [2]byte
	io.ReadFull(conn, g[:])

	// Request with domain name type (Socks5 allows IP literals as domain strings).
	host := "127.0.0.1"
	port := uint16(9082)
	req := make([]byte, 7+len(host))
	req[0] = 0x05
	req[1] = 0x01 // CONNECT
	req[2] = 0x00
	req[3] = 0x03 // domain
	req[4] = byte(len(host))
	copy(req[5:], host)
	binary.BigEndian.PutUint16(req[len(req)-2:], port)

	conn.Write(req)

	var hdr [4]byte
	io.ReadFull(conn, hdr[:])
	if hdr[1] != 0x00 {
		conn.Close()
		t.Fatalf("expected success reply, got code %d", hdr[1])
	}
	// skip bound addr
	switch hdr[3] {
	case 0x01:
		var tail [6]byte
		io.ReadFull(conn, tail[:])
	case 0x03:
		var domLen [1]byte
		io.ReadFull(conn, domLen[:])
		tail := make([]byte, domLen[0]+2)
		io.ReadFull(conn, tail)
	case 0x04:
		var tail [18]byte
		io.ReadFull(conn, tail[:])
	}

	conn.Write([]byte("hello"))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "domain-ok" {
		t.Errorf("expected 'domain-ok', got %q", buf[:n])
	}

	conn.Close()
	srv.Close()
	wg.Wait()
}

func TestSocks5_InvalidVersion(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send SOCKS4 greeting (version 0x04).
	conn.Write([]byte{0x04, 0x01, 0x00})

	// The server should close the connection after detecting bad version.
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection close after invalid version")
	}

	srv.Close()
	wg.Wait()
}

func TestSocks5_UnsupportedCommand(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Greeting.
	conn.Write([]byte{0x05, 0x01, 0x00})
	var g [2]byte
	io.ReadFull(conn, g[:])

	// BIND command (0x02) — not supported.
	req := make([]byte, 10)
	req[0] = 0x05
	req[1] = 0x02 // BIND
	req[2] = 0x00
	req[3] = 0x01 // IPv4
	// zero IPv4 + zero port
	conn.Write(req)

	var hdr [4]byte
	io.ReadFull(conn, hdr[:])
	if hdr[1] != 0x07 { // CmdNotSupported
		t.Errorf("expected reply code 0x07 (CmdNotSupported), got 0x%02x", hdr[1])
	}

	srv.Close()
	wg.Wait()
}

func TestSocks5_CloseStopsServer(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	// Verify listener is active.
	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("expected listener to be active: %v", err)
	}
	conn.Close()

	// Close the server.
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Serve should return nil after close.
	if err := <-done; err != nil {
		t.Errorf("expected nil error from Serve after Close, got %v", err)
	}

	// Listener should no longer accept.
	_, err = net.Dial("tcp", srv.Addr().String())
	if err == nil {
		t.Error("expected listener to be closed")
	}
}

func TestSocks5_WithDialTimeout(t *testing.T) {
	ns, err := shim.NewNetstack("10.100.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0",
		shim.WithDialTimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	// Try to connect to an unreachable address. Should time out.
	conn, err := socks5Dial(srv.Addr().String(), "10.255.255.255:9999")
	if err == nil {
		conn.Close()
		t.Fatal("expected timeout error when dialing unreachable address")
	}

	srv.Close()
	wg.Wait()
}

func TestSocks5_ConcurrentConnections(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ln, err := ns.ListenTCP("127.0.0.1:9083")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	// Echo server on netstack.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) // echo
			}()
		}
	}()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	proxyAddr := srv.Addr().String()
	const numConns = 10

	var clientWg sync.WaitGroup
	errCh := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		clientWg.Add(1)
		go func(idx int) {
			defer clientWg.Done()
			conn, err := socks5Dial(proxyAddr, "127.0.0.1:9083")
			if err != nil {
				errCh <- fmt.Errorf("conn %d: dial: %w", idx, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("hello-%d", idx)
			if _, err := conn.Write([]byte(msg)); err != nil {
				errCh <- fmt.Errorf("conn %d: write: %w", idx, err)
				return
			}

			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			if err != nil {
				errCh <- fmt.Errorf("conn %d: read: %w", idx, err)
				return
			}
			if string(buf[:n]) != msg {
				errCh <- fmt.Errorf("conn %d: expected %q, got %q", idx, msg, buf[:n])
			}
		}(i)
	}

	clientWg.Wait()
	close(errCh)

	for e := range errCh {
		t.Error(e)
	}

	srv.Close()
	wg.Wait()
}

func TestSocks5_BidirectionalData(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ln, err := ns.ListenTCP("127.0.0.1:9084")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			for i := 0; i < 3; i++ {
				n, rErr := conn.Read(buf)
				if rErr != nil {
					return
				}
				conn.Write([]byte(fmt.Sprintf("echo:%s", buf[:n])))
			}
		}
	}()

	srv, err := shim.NewSocks5Server(ns, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	defer srv.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := socks5Dial(srv.Addr().String(), "127.0.0.1:9084")
	if err != nil {
		t.Fatalf("socks5Dial: %v", err)
	}

	messages := []string{"ping", "hello", "world"}
	buf := make([]byte, 1024)

	for _, m := range messages {
		if _, err := conn.Write([]byte(m)); err != nil {
			conn.Close()
			t.Fatalf("Write %q: %v", m, err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			t.Fatalf("Read after %q: %v", m, err)
		}
		expected := fmt.Sprintf("echo:%s", m)
		if string(buf[:n]) != expected {
			t.Errorf("expected %q, got %q", expected, buf[:n])
		}
	}

	conn.Close()
	srv.Close()
	wg.Wait()
}
