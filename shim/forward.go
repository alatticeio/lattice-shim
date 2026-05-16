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
	"fmt"
	"io"
	"net"
	"sync"
)

// ForwardRule maps an overlay TCP port to a local target address.
type ForwardRule struct {
	OverlayPort uint16 // port to listen on within the netstack at overlayIP
	TargetAddr  string // local address to forward to, e.g. "127.0.0.1:8080"
}

// ForwardListener listens on the netstack's overlay IP for each ForwardRule
// and relays accepted TCP connections to the corresponding local target.
// Policy checks are NOT performed here — they are enforced on the outbound
// side by the originating sandbox's EgressFilter.
type ForwardListener struct {
	ns        *Netstack
	overlayIP string
	rules     []ForwardRule

	listeners []net.Listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewForwardListener creates a ForwardListener. Call Start to begin accepting.
func NewForwardListener(ns *Netstack, overlayIP string, rules []ForwardRule) *ForwardListener {
	return &ForwardListener{ns: ns, overlayIP: overlayIP, rules: rules}
}

// Start binds a TCP listener on the netstack for each ForwardRule and
// launches accept goroutines. Returns an error if any listener fails to bind;
// on error, all already-bound listeners are closed before returning.
func (f *ForwardListener) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	f.cancel = cancel

	for _, rule := range f.rules {
		addr := net.JoinHostPort(f.overlayIP, fmt.Sprintf("%d", rule.OverlayPort))
		ln, err := f.ns.ListenTCP(addr)
		if err != nil {
			cancel()
			for _, l := range f.listeners {
				l.Close()
			}
			f.listeners = nil
			return fmt.Errorf("forward listen %s: %w", addr, err)
		}
		f.listeners = append(f.listeners, ln)

		target := rule.TargetAddr
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.acceptLoop(ctx, ln, target)
		}()
	}
	return nil
}

// Close stops all listeners and waits for all goroutines to finish.
func (f *ForwardListener) Close() error {
	if f.cancel != nil {
		f.cancel()
	}
	for _, ln := range f.listeners {
		ln.Close()
	}
	f.wg.Wait()
	return nil
}

func (f *ForwardListener) acceptLoop(ctx context.Context, ln net.Listener, targetAddr string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.forwardConn(ctx, conn, targetAddr)
		}()
	}
}

func (f *ForwardListener) forwardConn(ctx context.Context, src net.Conn, targetAddr string) {
	defer src.Close()
	dst, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer dst.Close()
	relay(src, dst)
}

// relay copies data bidirectionally between a and b, using half-close when
// available so each side can observe EOF cleanly.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src) //nolint:errcheck
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite() //nolint:errcheck
		} else {
			dst.Close()
		}
	}
	go cp(b, a)
	go cp(a, b)
	wg.Wait()
}
