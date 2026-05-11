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

// Verdict constants for audit events.
const (
	VerdictAllow = "allow"
	VerdictDrop  = "drop"
)

// AuditEvent records a single policy decision made by the netstack.
type AuditEvent struct {
	Identity string `json:"identity"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
	Verdict  string `json:"verdict"` // "allow" | "drop"
}

// AuditWriter receives audit events for every allow/drop verdict produced by
// the netstack. The implementation is injected by the caller.
type AuditWriter interface {
	Write(event AuditEvent) error
}
