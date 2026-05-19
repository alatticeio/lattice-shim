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

package shim

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Version = 0x05

	socks5AuthNone = 0x00

	socks5CmdConnect = 0x01

	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04

	socks5ReplySucceeded        = 0x00
	socks5ReplyGeneralFailure   = 0x01
	socks5ReplyCmdNotSupported  = 0x07
	socks5ReplyAddrNotSupported = 0x08
)

// ContextDialer is the interface for dialing connections through a
// network stack. Both *Netstack and any type with a matching DialContext
// method satisfy this interface.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Socks5Server is a SOCKS5 proxy that tunnels TCP connections through a
// ContextDialer. It listens on the host network and routes each proxied
// connection through dial.DialContext so that policy and audit hooks
// apply transparently.
type Socks5Server struct {
	dial ContextDialer
	ln   net.Listener

	dialTimeout time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Socks5Option configures a Socks5Server.
type Socks5Option func(*Socks5Server)

// WithDialTimeout sets the timeout for each proxied dial through the
// netstack. The default is 30 seconds.
func WithDialTimeout(d time.Duration) Socks5Option {
	return func(s *Socks5Server) {
		s.dialTimeout = d
	}
}

// NewSocks5Server creates a SOCKS5 server that listens on the given host
// address (e.g., "127.0.0.1:1080") and tunnels TCP connections through
// the ContextDialer.
func NewSocks5Server(dial ContextDialer, addr string, opts ...Socks5Option) (*Socks5Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 listen: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Socks5Server{
		dial:        dial,
		ln:          ln,
		dialTimeout: 30 * time.Second,
		ctx:         ctx,
		cancel:      cancel,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Addr returns the listener's network address.
func (s *Socks5Server) Addr() net.Addr { return s.ln.Addr() }

// Serve accepts and handles SOCKS5 connections. It blocks until the
// listener is closed or an irrecoverable error occurs.
func (s *Socks5Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				return fmt.Errorf("socks5 accept: %w", err)
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Close shuts down the SOCKS5 server and waits for all active connections
// to finish.
func (s *Socks5Server) Close() error {
	s.cancel()
	s.ln.Close()
	s.wg.Wait()
	return nil
}

func (s *Socks5Server) handle(client net.Conn) {
	defer client.Close()

	// 1. Greeting (auth negotiation).
	if err := s.handleGreeting(client); err != nil {
		return
	}

	// 2. Request parsing.
	targetAddr, err := s.handleRequest(client)
	if err != nil {
		return
	}

	// 3. Dial through the netstack. Policy and audit hooks on ns apply.
	ctx, cancel := context.WithTimeout(s.ctx, s.dialTimeout)
	defer cancel()

	remote, err := s.dial.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		s.sendReply(client, socks5ReplyGeneralFailure, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		return
	}
	defer remote.Close()

	// 4. Send success reply with the bound address.
	s.sendReply(client, socks5ReplySucceeded, remote.LocalAddr())

	// 5. Bidirectional relay.
	s.relay(client, remote)
}

// handleGreeting reads the SOCKS5 greeting and responds with no-auth.
func (s *Socks5Server) handleGreeting(conn net.Conn) error {
	var buf [258]byte

	// Read version + nauth + auth methods.
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	if buf[0] != socks5Version {
		return fmt.Errorf("socks5: unsupported version %d", buf[0])
	}
	nauth := int(buf[1])
	if nauth > 0 {
		if _, err := io.ReadFull(conn, buf[:nauth]); err != nil {
			return err
		}
	}

	// Respond with no authentication required.
	_, err := conn.Write([]byte{socks5Version, socks5AuthNone})
	return err
}

// handleRequest reads the SOCKS5 request and returns the target address.
func (s *Socks5Server) handleRequest(conn net.Conn) (string, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != socks5Version {
		return "", fmt.Errorf("socks5: unsupported version %d in request", hdr[0])
	}
	if hdr[1] != socks5CmdConnect {
		s.sendReply(conn, socks5ReplyCmdNotSupported, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		return "", fmt.Errorf("socks5: unsupported command %d", hdr[1])
	}

	var host string
	switch hdr[3] {
	case socks5AddrIPv4:
		var addr [4]byte
		if _, err := io.ReadFull(conn, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	case socks5AddrDomain:
		var domLen [1]byte
		if _, err := io.ReadFull(conn, domLen[:]); err != nil {
			return "", err
		}
		dom := make([]byte, domLen[0])
		if _, err := io.ReadFull(conn, dom); err != nil {
			return "", err
		}
		host = string(dom)
	case socks5AddrIPv6:
		var addr [16]byte
		if _, err := io.ReadFull(conn, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	default:
		s.sendReply(conn, socks5ReplyAddrNotSupported, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		return "", fmt.Errorf("socks5: unsupported address type %d", hdr[3])
	}

	// Read port (2 bytes, big-endian).
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}

	return net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(port[:]))), nil
}

// sendReply writes a SOCKS5 reply to the client.
func (s *Socks5Server) sendReply(conn net.Conn, reply byte, addr net.Addr) {
	var buf [300]byte
	buf[0] = socks5Version
	buf[1] = reply
	buf[2] = 0x00 // reserved

	// Use the bound address if available, otherwise send zero addr.
	switch a := addr.(type) {
	case *net.TCPAddr:
		if ip4 := a.IP.To4(); ip4 != nil {
			buf[3] = socks5AddrIPv4
			copy(buf[4:8], ip4)
			binary.BigEndian.PutUint16(buf[8:10], uint16(a.Port))
			conn.Write(buf[:10])
			return
		}
		if ip6 := a.IP.To16(); ip6 != nil {
			buf[3] = socks5AddrIPv6
			copy(buf[4:20], ip6)
			binary.BigEndian.PutUint16(buf[20:22], uint16(a.Port))
			conn.Write(buf[:22])
			return
		}
	}
	// Fallback: IPv4 zero address.
	buf[3] = socks5AddrIPv4
	// addr bytes already zero
	conn.Write(buf[:10])
}

// relay copies data bidirectionally between client and remote. When one
// direction finishes, the other is unblocked by closing the connection.
func (s *Socks5Server) relay(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(remote, client)
		// Signal remote that no more data is coming from client.
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			remote.Close()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, remote)
		// Signal client that no more data is coming from remote.
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			client.Close()
		}
	}()

	wg.Wait()
}
