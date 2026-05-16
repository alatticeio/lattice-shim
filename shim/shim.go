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
	"net"
	"sync"
)

// Sandbox wires together a Netstack, Socks5Server, ForwardListener, and an
// optional PeerManager into a single coherent network subsystem.
// The caller injects policy, audit, and peer management via options.
type Sandbox struct {
	ns      *Netstack
	socks5  *Socks5Server    // nil if WithSOCKS5 not used
	forward *ForwardListener // nil if no WithForwardRule calls
	peers   PeerManager      // nil if WithPeerManager not used
	wg      sync.WaitGroup
}

type sandboxConfig struct {
	nsOpts       []NetstackOption
	socks5Addr   string
	forwardRules []ForwardRule
	peers        PeerManager
}

// Option configures a Sandbox.
type Option func(*sandboxConfig)

// WithNetstack passes NetstackOptions (WithIdentity, WithPolicy, WithAudit,
// etc.) through to the underlying Netstack.
func WithNetstack(opts ...NetstackOption) Option {
	return func(c *sandboxConfig) {
		c.nsOpts = append(c.nsOpts, opts...)
	}
}

// WithSOCKS5 starts a SOCKS5 proxy at addr (e.g. "127.0.0.1:1080").
// Workload processes set ALL_PROXY=socks5://127.0.0.1:1080 to route
// outbound traffic through the netstack (and thus through policy checks).
func WithSOCKS5(addr string) Option {
	return func(c *sandboxConfig) { c.socks5Addr = addr }
}

// WithForwardRule registers an inbound port-forward rule: connections
// arriving on overlayPort within the netstack are relayed to targetAddr on
// the host. Multiple calls add multiple rules.
func WithForwardRule(overlayPort uint16, targetAddr string) Option {
	return func(c *sandboxConfig) {
		c.forwardRules = append(c.forwardRules, ForwardRule{
			OverlayPort: overlayPort,
			TargetAddr:  targetAddr,
		})
	}
}

// WithPeerManager injects a PeerManager (typically a wireguard-go device
// wrapper from the caller). The main repo's WireGuardManager calls
// sb.AddPeer / sb.RemovePeer after subscribing to NATS NetMap changes.
func WithPeerManager(pm PeerManager) Option {
	return func(c *sandboxConfig) { c.peers = pm }
}

// New creates a Sandbox with the given overlay IP and options.
// overlayIP is the WireGuard overlay address assigned to this node (e.g.
// "10.100.0.1"). It is used as both the Netstack local address and the
// listen address for ForwardListener rules.
func New(overlayIP string, opts ...Option) (*Sandbox, error) {
	cfg := &sandboxConfig{}
	for _, o := range opts {
		o(cfg)
	}

	ns, err := NewNetstack(overlayIP, cfg.nsOpts...)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}

	sb := &Sandbox{ns: ns, peers: cfg.peers}

	if cfg.socks5Addr != "" {
		srv, err := NewSocks5Server(ns, cfg.socks5Addr)
		if err != nil {
			ns.Close()
			return nil, fmt.Errorf("socks5: %w", err)
		}
		sb.socks5 = srv
	}

	if len(cfg.forwardRules) > 0 {
		sb.forward = NewForwardListener(ns, overlayIP, cfg.forwardRules)
	}

	return sb, nil
}

// Start launches background goroutines for the SOCKS5 server and
// ForwardListener. It returns immediately; use Close to stop.
func (s *Sandbox) Start(ctx context.Context) error {
	if s.socks5 != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.socks5.Serve()
		}()
	}
	if s.forward != nil {
		if err := s.forward.Start(ctx); err != nil {
			return fmt.Errorf("forward listener: %w", err)
		}
	}
	return nil
}

// Close stops all components and waits for goroutines to exit.
func (s *Sandbox) Close() error {
	var firstErr error
	set := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	if s.socks5 != nil {
		set(s.socks5.Close())
	}
	if s.forward != nil {
		set(s.forward.Close())
	}
	set(s.ns.Close())
	s.wg.Wait()
	return firstErr
}

// Netstack returns the underlying gVisor netstack for advanced use (e.g.
// attaching a wireguard-go channel endpoint).
func (s *Sandbox) Netstack() *Netstack { return s.ns }

// Socks5Addr returns the listening address of the SOCKS5 server, or ""
// if WithSOCKS5 was not configured.
func (s *Sandbox) Socks5Addr() string {
	if s.socks5 == nil {
		return ""
	}
	return s.socks5.Addr().String()
}

// AddPeer delegates to the injected PeerManager.
// Returns an error if no PeerManager was configured.
func (s *Sandbox) AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error {
	if s.peers == nil {
		return fmt.Errorf("sandbox: no PeerManager configured")
	}
	return s.peers.AddPeer(pubKey, allowedIPs, endpoint)
}

// RemovePeer delegates to the injected PeerManager.
func (s *Sandbox) RemovePeer(pubKey [32]byte) error {
	if s.peers == nil {
		return fmt.Errorf("sandbox: no PeerManager configured")
	}
	return s.peers.RemovePeer(pubKey)
}

// SetPrivateKey delegates to the injected PeerManager.
func (s *Sandbox) SetPrivateKey(key [32]byte) error {
	if s.peers == nil {
		return fmt.Errorf("sandbox: no PeerManager configured")
	}
	return s.peers.SetPrivateKey(key)
}
