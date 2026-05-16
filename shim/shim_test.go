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
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
	"github.com/alatticeio/lattice-shim/shim/internal/test"
)

func TestSandbox_PeerManager(t *testing.T) {
	pm := &test.MockPeerManager{}

	sb, err := shim.New("10.0.0.1", shim.WithPeerManager(pm))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	var key [32]byte
	key[0] = 1
	_, subnet, _ := net.ParseCIDR("10.0.0.2/32")
	if err := sb.AddPeer(key, []net.IPNet{*subnet}, "1.2.3.4:51820"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	if !pm.HasPeer(key) {
		t.Error("expected peer to be added to MockPeerManager")
	}

	if err := sb.RemovePeer(key); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if pm.HasPeer(key) {
		t.Error("expected peer to be removed from MockPeerManager")
	}
}

func TestSandbox_SOCKSProxy(t *testing.T) {
	// Listener and SOCKS5 proxy share the same sandbox netstack (loopback within gVisor).
	sb, err := shim.New("127.0.0.1", shim.WithSOCKS5("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	// Echo server on the sandbox's own netstack.
	ln, err := sb.Netstack().ListenTCP("127.0.0.1:9300")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	conn, err := socks5Dial(sb.Socks5Addr(), "127.0.0.1:9300")
	if err != nil {
		t.Fatalf("socks5Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("via sandbox socks5")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	io.ReadFull(conn, buf)
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestSandbox_ForwardRule(t *testing.T) {
	echoAddr := startEchoServer(t)

	sb, err := shim.New("127.0.0.1",
		shim.WithForwardRule(9301, echoAddr),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	conn, err := sb.Netstack().DialContext(ctx, "tcp", "127.0.0.1:9301")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	msg := []byte("via sandbox forward")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	io.ReadFull(conn, buf)
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestSandbox_EgressPolicyDeny(t *testing.T) {
	filter := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: true})
	audit := &test.MockAuditWriter{}

	sb, err := shim.New("10.100.0.1",
		shim.WithNetstack(
			shim.WithIdentity("sandbox-test"),
			shim.WithPolicy(filter),
			shim.WithAudit(audit),
		),
		shim.WithSOCKS5("127.0.0.1:0"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	_, err = socks5Dial(sb.Socks5Addr(), "10.0.0.1:443")
	if err == nil {
		t.Fatal("expected SOCKS5 failure when EgressFilter denies all")
	}
}

func TestSandbox_Close(t *testing.T) {
	sb, err := shim.New("127.0.0.1", shim.WithSOCKS5("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sb.Start(ctx)

	time.Sleep(50 * time.Millisecond)

	addr := sb.Socks5Addr()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("expected SOCKS5 active before Close: %v", err)
	}
	conn.Close()

	sb.Close()

	_, err = net.Dial("tcp", addr)
	if err == nil {
		t.Error("expected SOCKS5 unreachable after Close")
	}
}

func TestSandbox_NoPeerManager(t *testing.T) {
	sb, err := shim.New("10.0.0.1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	var key [32]byte
	_, subnet, _ := net.ParseCIDR("10.0.0.2/32")
	err = sb.AddPeer(key, []net.IPNet{*subnet}, "1.2.3.4:51820")
	if err == nil {
		t.Error("expected error when no PeerManager configured")
	}
}
