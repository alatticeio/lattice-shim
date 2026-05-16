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
	"net"
	"sync/atomic"
)

// EgressPolicy defines which outbound destinations are permitted.
type EgressPolicy struct {
	// AllowedCIDRs is the list of IP ranges that are always permitted.
	AllowedCIDRs []net.IPNet

	// DefaultDeny controls what happens when dstIP matches no AllowedCIDR.
	// true  → deny (whitelist mode)
	// false → allow (audit-only / allow-all mode)
	DefaultDeny bool
}

// EgressFilter implements PolicyChecker using a CIDR-based allowlist.
// The policy can be replaced atomically at runtime via Update — no restart
// required. This makes it suitable for NATS-pushed policy changes where the
// main repo calls Update after receiving a new policy payload.
type EgressFilter struct {
	policy atomic.Pointer[EgressPolicy]
}

// NewEgressFilter creates an EgressFilter with the given initial policy.
func NewEgressFilter(initial EgressPolicy) *EgressFilter {
	f := &EgressFilter{}
	f.policy.Store(&initial)
	return f
}

// Allow implements PolicyChecker. It returns true if dstIP is covered by any
// AllowedCIDR, or if DefaultDeny is false (allow-all mode). The identity and
// dstPort parameters are accepted for interface compatibility but are not used
// in CIDR matching — port-level policy is enforced at the application layer.
func (f *EgressFilter) Allow(_ string, dstIP net.IP, _ uint16) bool {
	p := f.policy.Load()
	for i := range p.AllowedCIDRs {
		if p.AllowedCIDRs[i].Contains(dstIP) {
			return true
		}
	}
	return !p.DefaultDeny
}

// Update atomically replaces the current policy. Ongoing Allow calls that
// began before Update returns may observe the old or new policy; calls that
// begin after Update returns always observe the new policy.
func (f *EgressFilter) Update(p EgressPolicy) {
	f.policy.Store(&p)
}
