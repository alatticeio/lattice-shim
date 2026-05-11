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

/*
Package shim provides a zero-privilege user-space TCP/IP network stack
backed by gVisor, with optional wireguard-go attachment and pluggable
policy and audit hooks. It has no dependency on Lattice CRDs, NATS, or
any Lattice control-plane components.

# Architecture

The core type is Netstack — a user-space TCP/IP stack that provides
DialContext and ListenTCP. Callers inject optional BeforeDial/AfterDial
hooks for policy checking, audit writing, rate limiting, or metrics.

	┌──────────────────────────────┐
	│          Netstack            │
	│  Identity string             │
	│  BeforeDial func (optional)  │
	│  AfterDial  func (optional)  │
	│  ┌────────────────────────┐  │
	│  │  gVisor user-space     │  │
	│  │  TCP/IP stack          │  │
	│  └────────────────────────┘  │
	└──────────────────────────────┘

The convenience functions WithPolicy and WithAudit adapt the
PolicyChecker and AuditWriter interfaces into BeforeDial/AfterDial hooks.

# Dependencies

This package imports only the Go standard library plus gvisor.dev/gvisor
and (optionally) golang.zx2c4.com/wireguard. It has no compile-time
dependency on any control-plane components.

# Usage

	// Simplest usage: no policy, no audit.
	ns, _ := shim.NewNetstack("10.100.0.1")
	defer ns.Close()
	conn, _ := ns.DialContext(ctx, "tcp", "1.2.3.4:443")

	// With identity and hooks.
	ns, _ := shim.NewNetstack("10.100.0.1",
	    shim.WithIdentity("my-service/instance-3"),
	    shim.WithBeforeDial(func(id, network, addr string) error {
	        if !isAllowed(addr) { return errors.New("denied") }
	        return nil
	    }),
	    shim.WithAfterDial(func(id, network, addr string, conn net.Conn, err error) {
	        log.Printf("dial: id=%s addr=%s err=%v", id, addr, err)
	    }),
	)

	// With PolicyChecker / AuditWriter interfaces.
	ns, _ := shim.NewNetstack("10.100.0.1",
	    shim.WithIdentity("sandbox:agent-1"),
	    shim.WithPolicy(myPolicy),
	    shim.WithAudit(myAudit),
	)
*/
package shim
