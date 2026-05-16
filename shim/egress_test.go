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
	"net"
	"testing"

	"github.com/alatticeio/lattice-shim/shim"
)

func parseCIDR(t *testing.T, s string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return *n
}

func parseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("ParseIP(%q) returned nil", s)
	}
	return ip
}

func TestEgressFilter_DefaultAllowAll(t *testing.T) {
	// DefaultDeny=false with no CIDRs: allow everything.
	f := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: false})

	cases := []string{"10.0.0.1", "192.168.1.1", "8.8.8.8", "172.16.0.1"}
	for _, ip := range cases {
		if !f.Allow("sandbox-a", parseIP(t, ip), 443) {
			t.Errorf("expected Allow for %s, got deny", ip)
		}
	}
}

func TestEgressFilter_DefaultDenyNoRules(t *testing.T) {
	// DefaultDeny=true with no CIDRs: deny everything.
	f := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: true})

	cases := []string{"10.0.0.1", "192.168.1.1", "8.8.8.8"}
	for _, ip := range cases {
		if f.Allow("sandbox-a", parseIP(t, ip), 443) {
			t.Errorf("expected Deny for %s, got allow", ip)
		}
	}
}

func TestEgressFilter_CIDRAllows(t *testing.T) {
	// DefaultDeny=true, only 10.0.0.0/8 allowed.
	f := shim.NewEgressFilter(shim.EgressPolicy{
		DefaultDeny:  true,
		AllowedCIDRs: []net.IPNet{parseCIDR(t, "10.0.0.0/8")},
	})

	allowed := []string{"10.0.0.1", "10.255.255.255", "10.100.0.2"}
	for _, ip := range allowed {
		if !f.Allow("sandbox-a", parseIP(t, ip), 80) {
			t.Errorf("expected Allow for %s (in 10.0.0.0/8), got deny", ip)
		}
	}

	denied := []string{"192.168.1.1", "172.16.0.1", "8.8.8.8"}
	for _, ip := range denied {
		if f.Allow("sandbox-a", parseIP(t, ip), 80) {
			t.Errorf("expected Deny for %s (not in 10.0.0.0/8), got allow", ip)
		}
	}
}

func TestEgressFilter_MultipleCIDRs(t *testing.T) {
	f := shim.NewEgressFilter(shim.EgressPolicy{
		DefaultDeny: true,
		AllowedCIDRs: []net.IPNet{
			parseCIDR(t, "10.0.0.0/8"),
			parseCIDR(t, "192.168.0.0/16"),
		},
	})

	if !f.Allow("x", parseIP(t, "10.1.2.3"), 80) {
		t.Error("expected allow for 10.1.2.3")
	}
	if !f.Allow("x", parseIP(t, "192.168.99.1"), 80) {
		t.Error("expected allow for 192.168.99.1")
	}
	if f.Allow("x", parseIP(t, "8.8.8.8"), 80) {
		t.Error("expected deny for 8.8.8.8")
	}
}

func TestEgressFilter_Update(t *testing.T) {
	// Start as allow-all, then switch to deny-all.
	f := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: false})

	ip := parseIP(t, "10.0.0.1")
	if !f.Allow("sandbox", ip, 443) {
		t.Fatal("expected allow before Update")
	}

	f.Update(shim.EgressPolicy{DefaultDeny: true})

	if f.Allow("sandbox", ip, 443) {
		t.Error("expected deny after Update to DefaultDeny=true")
	}
}

func TestEgressFilter_UpdateCIDR(t *testing.T) {
	// Start deny-all, then add a CIDR, verify previously-denied IP is now allowed.
	f := shim.NewEgressFilter(shim.EgressPolicy{DefaultDeny: true})

	ip := parseIP(t, "10.0.0.1")
	if f.Allow("sandbox", ip, 443) {
		t.Fatal("expected deny before Update")
	}

	f.Update(shim.EgressPolicy{
		DefaultDeny:  true,
		AllowedCIDRs: []net.IPNet{parseCIDR(t, "10.0.0.0/8")},
	})

	if !f.Allow("sandbox", ip, 443) {
		t.Error("expected allow after adding 10.0.0.0/8 CIDR")
	}
}

func TestEgressFilter_ImplementsPolicyChecker(t *testing.T) {
	// Compile-time check: EgressFilter implements PolicyChecker.
	var _ shim.PolicyChecker = shim.NewEgressFilter(shim.EgressPolicy{})
}
