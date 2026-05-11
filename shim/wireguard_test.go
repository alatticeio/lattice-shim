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
	"sync"
	"testing"

	"github.com/alatticeio/lattice-shim/shim"
)

type mockBind struct {
	mu      sync.Mutex
	written [][]byte
	reads   [][]byte
	readIdx int
	closed  bool
}

func (m *mockBind) Write(packet []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.written = append(m.written, append([]byte(nil), packet...))
	return nil
}

func (m *mockBind) Read() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readIdx >= len(m.reads) {
		return nil, nil
	}
	p := m.reads[m.readIdx]
	m.readIdx++
	return p, nil
}

func (m *mockBind) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func TestWireGuardEndpoint_AttachClose(t *testing.T) {
	bind := &mockBind{}

	ep := &shim.WireGuardEndpoint{
		Close: bind.Close,
	}

	if err := ep.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bind.closed {
		t.Error("expected bind to be closed")
	}
}

func TestWireGuardEndpoint_DataFlow(t *testing.T) {
	inboundPackets := make([][]byte, 0)
	outboundPackets := make([][]byte, 0)

	var mu sync.Mutex

	ep := &shim.WireGuardEndpoint{
		Outbound: func(packet []byte) error {
			mu.Lock()
			outboundPackets = append(outboundPackets, append([]byte(nil), packet...))
			mu.Unlock()
			return nil
		},
		Inbound: func(packet []byte) error {
			mu.Lock()
			inboundPackets = append(inboundPackets, append([]byte(nil), packet...))
			mu.Unlock()
			return nil
		},
		Close: func() error { return nil },
	}

	testPacket := []byte{0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00}
	if err := ep.Outbound(testPacket); err != nil {
		t.Fatalf("Outbound: %v", err)
	}

	decryptedPacket := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00}
	if err := ep.Inbound(decryptedPacket); err != nil {
		t.Fatalf("Inbound: %v", err)
	}

	mu.Lock()
	if len(outboundPackets) != 1 {
		t.Errorf("expected 1 outbound packet, got %d", len(outboundPackets))
	}
	if len(inboundPackets) != 1 {
		t.Errorf("expected 1 inbound packet, got %d", len(inboundPackets))
	}
	mu.Unlock()
}

func TestWireGuardBind_Mock(t *testing.T) {
	bind := &mockBind{
		reads: [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05},
		},
	}

	if err := bind.Write([]byte{0xaa, 0xbb}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := bind.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(data) != 3 || data[0] != 0x01 {
		t.Errorf("unexpected first read: %v", data)
	}

	data, err = bind.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(data) != 2 || data[0] != 0x04 {
		t.Errorf("unexpected second read: %v", data)
	}

	if len(bind.written) != 1 || bind.written[0][0] != 0xaa {
		t.Errorf("unexpected written data: %v", bind.written)
	}
}
