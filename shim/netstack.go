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
	"fmt"
	"net"
)

// NetstackOption is a functional option for configuring a Netstack.
type NetstackOption func(ns *Netstack) error

// WithIdentity sets the identity string on the Netstack. It is passed to
// BeforeDial and AfterDial hooks.
func WithIdentity(id string) NetstackOption {
	return func(ns *Netstack) error {
		ns.Identity = id
		return nil
	}
}

// WithBeforeDial sets a hook that is called before every DialContext. If the
// function returns a non-nil error, the dial is aborted.
func WithBeforeDial(fn func(identity, network, addr string) error) NetstackOption {
	return func(ns *Netstack) error {
		ns.BeforeDial = fn
		return nil
	}
}

// WithAfterDial sets a hook that is called after every DialContext,
// regardless of success or failure. The conn is nil on error.
func WithAfterDial(fn func(identity, network, addr string, conn net.Conn, err error)) NetstackOption {
	return func(ns *Netstack) error {
		ns.AfterDial = fn
		return nil
	}
}

// WithPolicy is a convenience option that wraps a PolicyChecker as a
// BeforeDial hook. If the policy denies the connection, DialContext returns
// an error before any network call is made.
func WithPolicy(pc PolicyChecker) NetstackOption {
	return WithBeforeDial(func(identity, network, addr string) error {
		dstIP, dstPort, err := parseAddr(network, addr)
		if err != nil {
			return err
		}
		if !pc.Allow(identity, dstIP, dstPort) {
			return fmt.Errorf("connection to %s denied by policy", addr)
		}
		return nil
	})
}

// WithAudit is a convenience option that wraps an AuditWriter as an
// AfterDial hook. An audit event is written for every DialContext call.
func WithAudit(aw AuditWriter) NetstackOption {
	return WithAfterDial(func(identity, network, addr string, conn net.Conn, err error) {
		dstIP, dstPort, parseErr := parseAddr(network, addr)
		if parseErr != nil {
			return
		}
		verdict := VerdictAllow
		if err != nil {
			verdict = VerdictDrop
		}
		aw.Write(AuditEvent{
			Identity: identity,
			DstIP:    dstIP.String(),
			DstPort:  dstPort,
			Protocol: network,
			Verdict:  verdict,
		})
	})
}

// parseAddr parses a "host:port" address into net.IP and uint16 port.
func parseAddr(network, addr string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid IP in address %q", addr)
	}
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port in address %q: %w", addr, err)
	}
	return ip, uint16(port), nil
}
