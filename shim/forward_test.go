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
	"io"
	"net"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
)

// startEchoServer starts a real TCP echo server on the host OS and returns
// its address. The server echoes each read back to the sender.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestForwardListener_BasicRelay(t *testing.T) {
	echoAddr := startEchoServer(t)

	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	fwd := shim.NewForwardListener(ns, "127.0.0.1", []shim.ForwardRule{
		{OverlayPort: 9200, TargetAddr: echoAddr},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer fwd.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:9200")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello forward")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestForwardListener_MultipleRules(t *testing.T) {
	echo1 := startEchoServer(t)
	echo2 := startEchoServer(t)

	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	fwd := shim.NewForwardListener(ns, "127.0.0.1", []shim.ForwardRule{
		{OverlayPort: 9201, TargetAddr: echo1},
		{OverlayPort: 9202, TargetAddr: echo2},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer fwd.Close()

	time.Sleep(50 * time.Millisecond)

	for _, tc := range []struct {
		port string
		msg  string
	}{
		{"9201", "msg-to-echo1"},
		{"9202", "msg-to-echo2"},
	} {
		conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:"+tc.port)
		if err != nil {
			t.Fatalf("port %s DialContext: %v", tc.port, err)
		}
		if _, err := conn.Write([]byte(tc.msg)); err != nil {
			conn.Close()
			t.Fatalf("port %s Write: %v", tc.port, err)
		}
		buf := make([]byte, len(tc.msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			t.Fatalf("port %s ReadFull: %v", tc.port, err)
		}
		if string(buf) != tc.msg {
			t.Errorf("port %s: expected %q, got %q", tc.port, tc.msg, buf)
		}
		conn.Close()
	}
}

func TestForwardListener_CloseStops(t *testing.T) {
	echoAddr := startEchoServer(t)

	ns, err := shim.NewNetstack("127.0.0.1")
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	fwd := shim.NewForwardListener(ns, "127.0.0.1", []shim.ForwardRule{
		{OverlayPort: 9203, TargetAddr: echoAddr},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify active before close.
	conn, err := ns.DialContext(ctx, "tcp", "127.0.0.1:9203")
	if err != nil {
		t.Fatalf("expected listener active: %v", err)
	}
	conn.Close()

	// Close the forward listener.
	if err := fwd.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Dialing should now fail.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	_, err = ns.DialContext(ctx2, "tcp", "127.0.0.1:9203")
	if err == nil {
		t.Error("expected dial to fail after Close")
	}
}
