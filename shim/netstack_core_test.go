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
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
)

func TestNetstack_TCP(t *testing.T) {
	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	ln, err := ns.ListenTCP("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	msg := []byte("hello from gVisor")

	errCh := make(chan error, 1)
	go func() {
		conn, aErr := ln.Accept()
		if aErr != nil {
			errCh <- aErr
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, rErr := conn.Read(buf)
		if rErr != nil {
			errCh <- rErr
			return
		}
		if string(buf[:n]) != string(msg) {
			t.Errorf("expected %q, got %q", msg, buf[:n])
			errCh <- nil
			return
		}
		_, wErr := conn.Write([]byte("ack"))
		errCh <- wErr
	}()

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	ack := make([]byte, 1024)
	n, err := conn.Read(ack)
	if err != nil {
		t.Fatalf("Read ack: %v", err)
	}
	if string(ack[:n]) != "ack" {
		t.Errorf("expected 'ack', got %q", ack[:n])
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
