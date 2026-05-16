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

import "net"

// WireGuardBind describes the minimal interface the netstack bridge needs to
// hand packets to wireguard-go for encryption and UDP delivery.
type WireGuardBind interface {
	Write(packet []byte) error
	Read() ([]byte, error)
	Close() error
}

// WireGuardEndpoint bridges the gVisor netstack (via a channel endpoint or
// equivalent packet I/O) to wireguard-go. The concrete implementation is
// provided by the caller (the Lattice main repo injects gVisor's
// channel.Endpoint and wireguard-go's device.Bind).
type WireGuardEndpoint struct {
	// Outbound receives raw IP packets from the netstack and feeds them to
	// wireguard-go for encryption.
	Outbound func(packet []byte) error

	// Inbound receives decrypted IP packets from wireguard-go and injects
	// them into the netstack.
	Inbound func(packet []byte) error

	// Close releases the underlying resources.
	Close func() error
}

// PeerManager manages WireGuard peers. The implementation (typically a
// wireguard-go device wrapper) is injected by the caller; shim itself does
// not import wireguard-go.
type PeerManager interface {
	AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error
	RemovePeer(pubKey [32]byte) error
	SetPrivateKey(key [32]byte) error
}
