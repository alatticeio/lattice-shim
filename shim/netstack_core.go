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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Netstack is a user-space TCP/IP network stack backed by gVisor. It provides
// DialContext and ListenTCP with optional BeforeDial/AfterDial hooks.
type Netstack struct {
	// Identity is an arbitrary string supplied by the caller (e.g.
	// "my-service/instance-3"). It is passed to BeforeDial and AfterDial
	// hooks and has no intrinsic meaning to the netstack itself.
	Identity string

	// BeforeDial is called before every DialContext. If it returns a
	// non-nil error, the dial is aborted and the error is returned to the
	// caller. AfterDial is still invoked with the error.
	BeforeDial func(identity, network, addr string) error

	// AfterDial is called after every DialContext, regardless of success
	// or failure. The conn is nil on error.
	AfterDial func(identity, network, addr string, conn net.Conn, err error)

	localIP string
	s       *stack.Stack
	ch      *channel.Endpoint
	nicID   tcpip.NICID
}

// NewNetstack creates a user-space netstack with the given local IP address.
// Options such as WithIdentity, WithBeforeDial and WithAfterDial can be
// passed to configure hooks.
func NewNetstack(localIP string, opts ...NetstackOption) (*Netstack, error) {
	ns := &Netstack{localIP: localIP}
	for _, o := range opts {
		if err := o(ns); err != nil {
			return nil, err
		}
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	// Loopback NIC.
	loEp := loopback.New()
	loID := s.NextNICID()
	if err := s.CreateNIC(loID, loEp); err != nil {
		return nil, fmt.Errorf("CreateNIC(loopback): %s", err)
	}
	loAddr := tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			PrefixLen: 8,
		},
	}
	if err := s.AddProtocolAddress(loID, loAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress(loopback): %s", err)
	}

	// Channel NIC for outbound traffic.
	ch := channel.New(1024, 1500, "")
	nicID := s.NextNICID()
	if err := s.CreateNIC(nicID, ch); err != nil {
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}

	parsedIP := net.ParseIP(localIP).To4()
	if len(parsedIP) == 0 {
		return nil, fmt.Errorf("invalid IP address: %s", localIP)
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4Slice(parsedIP),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress: %s", err)
	}

	// Route loopback addresses to the loopback NIC; everything else
	// goes through the channel NIC for outbound (WireGuard overlay).
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4LoopbackSubnet, NIC: loID},
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})

	ns.s = s
	ns.ch = ch
	ns.nicID = nicID
	return ns, nil
}

// DialContext dials a remote address through the user-space netstack.
// BeforeDial and AfterDial hooks are invoked if set.
func (ns *Netstack) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if ns.s == nil {
		return nil, fmt.Errorf("netstack closed")
	}

	if ns.BeforeDial != nil {
		if err := ns.BeforeDial(ns.Identity, network, addr); err != nil {
			if ns.AfterDial != nil {
				ns.AfterDial(ns.Identity, network, addr, nil, err)
			}
			return nil, err
		}
	}

	conn, err := ns.dialContext(ctx, network, addr)

	if ns.AfterDial != nil {
		ns.AfterDial(ns.Identity, network, addr, conn, err)
	}
	return conn, err
}

func (ns *Netstack) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP in address %q", addr)
	}
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	fullAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(ip.To4()),
		Port: uint16(port),
	}

	switch network {
	case "tcp", "tcp4":
		return gonet.DialContextTCP(ctx, ns.s, fullAddr, header.IPv4ProtocolNumber)
	case "udp", "udp4":
		return gonet.DialUDP(ns.s, nil, &fullAddr, header.IPv4ProtocolNumber)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

// ListenTCP creates a TCP listener on the netstack at the given address.
func (ns *Netstack) ListenTCP(addr string) (net.Listener, error) {
	if ns.s == nil {
		return nil, fmt.Errorf("netstack closed")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP in address %q", addr)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	fullAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(ip.To4()),
		Port: uint16(port),
	}
	return gonet.ListenTCP(ns.s, fullAddr, header.IPv4ProtocolNumber)
}

// Channel returns the channel endpoint for wireguard-go attachment.
func (ns *Netstack) Channel() *channel.Endpoint { return ns.ch }

// Stack returns the underlying gVisor stack for advanced use.
func (ns *Netstack) Stack() *stack.Stack { return ns.s }

// Close destroys the netstack and channel endpoint.
func (ns *Netstack) Close() error {
	if ns.ch != nil {
		ns.ch.Close()
		ns.ch = nil
	}
	if ns.s != nil {
		ns.s.Destroy()
		ns.s = nil
	}
	return nil
}
