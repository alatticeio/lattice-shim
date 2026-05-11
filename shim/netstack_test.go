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
	"net"
	"strings"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
	"github.com/alatticeio/lattice-shim/shim/internal/test"
)

func TestNetstack_WithPolicy_Allow(t *testing.T) {
	policy := &test.MockPolicyChecker{}
	audit := &test.MockAuditWriter{}

	ns, err := shim.NewNetstack("127.0.0.1",
		shim.WithIdentity("test-instance"),
		shim.WithPolicy(policy),
		shim.WithAudit(audit),
	)
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ln, err := ns.ListenTCP("127.0.0.1:8081")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	msg := []byte("policy-checked message")

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			conn.Write([]byte("policy-ack"))
			if string(buf[:n]) != string(msg) {
				t.Errorf("mismatched message")
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:8081")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "policy-ack" {
		t.Errorf("expected 'policy-ack', got %q", buf[:n])
	}

	time.Sleep(50 * time.Millisecond)

	if audit.AllowedCount() != 1 {
		t.Errorf("expected 1 allow audit event, got %d", audit.AllowedCount())
	}

	call := policy.LastCall()
	if call == nil || call.Identity != "test-instance" {
		t.Errorf("expected policy check for 'test-instance', got %+v", call)
	}
}

func TestNetstack_WithPolicy_Deny(t *testing.T) {
	policy := &test.MockPolicyChecker{
		AllowFn: func(identity string, dstIP net.IP, dstPort uint16) bool {
			return false
		},
	}
	audit := &test.MockAuditWriter{}

	ns, err := shim.NewNetstack("10.100.0.1",
		shim.WithIdentity("test-instance"),
		shim.WithPolicy(policy),
		shim.WithAudit(audit),
	)
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ctx := context.Background()
	conn, err := ns.DialContext(ctx, "tcp", "10.99.99.99:6666")
	if err == nil {
		t.Fatal("expected error for denied connection")
	}
	if conn != nil {
		t.Fatal("expected nil conn for denied connection")
	}
	if !strings.Contains(err.Error(), "denied by policy") {
		t.Errorf("expected 'denied by policy' in error, got: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if audit.DroppedCount() != 1 {
		t.Errorf("expected 1 drop event, got %d", audit.DroppedCount())
	}
}

func TestNetstack_NoPolicy(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ln, err := ns.ListenTCP("127.0.0.1:8082")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			conn.Write([]byte("ok"))
			if n >= 0 {
				// read succeeded
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:8082")
	if err != nil {
		t.Fatalf("expected allow with nil policy, got: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	defer conn.Close()
}

func TestNetstack_BeforeDial_Deny(t *testing.T) {
	audit := &test.MockAuditWriter{}

	ns, err := shim.NewNetstack("10.100.0.1",
		shim.WithIdentity("test-instance"),
		shim.WithBeforeDial(func(identity, network, addr string) error {
			return &testError{msg: "custom deny"}
		}),
		shim.WithAudit(audit),
	)
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ctx := context.Background()
	conn, err := ns.DialContext(ctx, "tcp", "10.0.0.1:80")
	if err == nil {
		t.Fatal("expected error from BeforeDial")
	}
	if conn != nil {
		t.Fatal("expected nil conn when BeforeDial fails")
	}

	time.Sleep(50 * time.Millisecond)

	if audit.DroppedCount() != 1 {
		t.Errorf("expected 1 drop event, got %d", audit.DroppedCount())
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestNetstack_AfterDial_CalledOnSuccess(t *testing.T) {
	var afterIdentity, afterNetwork, afterAddr string
	var afterErr error
	var afterConn net.Conn

	ns, err := shim.NewNetstack("127.0.0.1",
		shim.WithIdentity("test-instance"),
		shim.WithAfterDial(func(identity, network, addr string, conn net.Conn, err error) {
			afterIdentity = identity
			afterNetwork = network
			afterAddr = addr
			afterConn = conn
			afterErr = err
		}),
	)
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ln, err := ns.ListenTCP("127.0.0.1:8083")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 64)
			n, _ := conn.Read(buf)
			if n >= 0 {
				// consume
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:8083")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if afterIdentity != "test-instance" {
		t.Errorf("expected identity 'test-instance', got %q", afterIdentity)
	}
	if afterNetwork != "tcp" {
		t.Errorf("expected network 'tcp', got %q", afterNetwork)
	}
	if afterAddr != "127.0.0.1:8083" {
		t.Errorf("expected addr '127.0.0.1:8083', got %q", afterAddr)
	}
	if afterErr != nil {
		t.Errorf("expected nil error in AfterDial, got %v", afterErr)
	}
	if afterConn == nil {
		t.Error("expected non-nil conn in AfterDial")
	}
}

func TestNetstack_Close(t *testing.T) {
	ns, err := shim.NewNetstack("10.100.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	ns.Close()

	_, err = ns.DialContext(context.Background(), "tcp", "10.0.0.1:80")
	if err == nil {
		t.Fatal("expected error after close")
	}
}
