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

// Package test provides mock implementations of shim interfaces for testing.
package test

import (
	"net"
	"sync"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
)

// MockPolicyChecker records Allow calls and returns a configurable result.
type MockPolicyChecker struct {
	mu      sync.Mutex
	AllowFn func(identity string, dstIP net.IP, dstPort uint16) bool
	Calls   []PolicyCall
}

// PolicyCall records a single Allow invocation.
type PolicyCall struct {
	Identity string
	DstIP    string
	DstPort  uint16
}

// Allow implements shim.PolicyChecker.
func (m *MockPolicyChecker) Allow(identity string, dstIP net.IP, dstPort uint16) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, PolicyCall{Identity: identity, DstIP: dstIP.String(), DstPort: dstPort})
	if m.AllowFn != nil {
		return m.AllowFn(identity, dstIP, dstPort)
	}
	return true // default allow-all
}

// LastCall returns the most recent Allow invocation, or nil.
func (m *MockPolicyChecker) LastCall() *PolicyCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Calls) == 0 {
		return nil
	}
	return &m.Calls[len(m.Calls)-1]
}

// MockAuditWriter records audit events in memory.
type MockAuditWriter struct {
	mu     sync.Mutex
	Events []shim.AuditEvent
}

// Write implements shim.AuditWriter.
func (m *MockAuditWriter) Write(ev shim.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, ev)
	return nil
}

// LastEvent returns the most recent audit event, or nil.
func (m *MockAuditWriter) LastEvent() *shim.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Events) == 0 {
		return nil
	}
	return &m.Events[len(m.Events)-1]
}

// AllowedCount returns the count of allow-verdict events.
func (m *MockAuditWriter) AllowedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.Events {
		if e.Verdict == shim.VerdictAllow {
			n++
		}
	}
	return n
}

// DroppedCount returns the count of drop-verdict events.
func (m *MockAuditWriter) DroppedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.Events {
		if e.Verdict == shim.VerdictDrop {
			n++
		}
	}
	return n
}

// MockConn implements net.Conn for testing. Always returns n=len(b) on Read.
type MockConn struct{}

func (MockConn) Read(b []byte) (int, error)       { return len(b), nil }
func (MockConn) Write(b []byte) (int, error)      { return len(b), nil }
func (MockConn) Close() error                     { return nil }
func (MockConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (MockConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443} }
func (MockConn) SetDeadline(time.Time) error      { return nil }
func (MockConn) SetReadDeadline(time.Time) error  { return nil }
func (MockConn) SetWriteDeadline(time.Time) error { return nil }
