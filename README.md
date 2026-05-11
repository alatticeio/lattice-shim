# lattice-shim

Zero-privilege user-space TCP/IP network stack backed by **gVisor**, with
optional **wireguard-go** attachment and pluggable **policy** and **audit** hooks.

This library has **no dependency** on Lattice CRDs, NATS, or any Lattice
control-plane components — it can be used in any project that needs a
user-space TCP/IP stack.

---

## How this avoids TUN devices

A standard WireGuard setup requires a **TUN device** — a virtual network
interface created by the kernel via `ioctl SIOCSIFFLAGS`, which needs
`CAP_NET_ADMIN` (typically root).

```
Standard approach (needs root):
  wireguard-go ──bind──▶ wf0 TUN device (kernel)
                          ├─ ioctl SIOCSIFFLAGS  ← needs CAP_NET_ADMIN
                          ├─ eBPF TC hook        ← needs CAP_BPF
                          └─ kernel TCP/IP stack

lattice-shim approach (zero privilege):
  wireguard-go ──bind──▶ gVisor netstack link endpoint (pure Go)
                          ├─ user-space TCP/IP   ← no kernel involvement
                          ├─ Go hooks            ← no eBPF needed
                          └─ Go audit callbacks  ← no ring buffer needed
```

**Key insight:** gVisor provides a complete, production-grade TCP/IP stack
implemented entirely in Go. By attaching wireguard-go directly to a gVisor
`channel.Endpoint` (a pure-Go link-layer endpoint), the entire data path
runs in user space: no TUN device, no `CAP_NET_ADMIN`, no root.

### Comparison

| Capability | Kernel TUN | lattice-shim (gVisor) |
|---|---|---|
| wireguard-go crypto | user space | user space (same) |
| TCP/IP stack | kernel | gVisor Go netstack |
| Policy enforcement | eBPF TC hook | Go BeforeDial hook |
| TUN device creation | `ioctl SIOCSIFFLAGS` | **not needed** |
| Privilege needed | `CAP_NET_ADMIN`, `CAP_BPF` | **none** |
| Start command | `sudo ...` | runs as normal user |

---

## Architecture

The core type is **`Netstack`** — a user-space TCP/IP stack. Callers inject
optional **BeforeDial** / **AfterDial** hooks for policy checking, audit
writing, rate limiting, or metrics.

```
┌──────────────────────────────┐
│          Netstack            │
│  Identity string             │
│  BeforeDial func (optional)  │
│  AfterDial  func (optional)  │
│  ┌────────────────────────┐  │
│  │  gVisor user-space     │  │
│  │  TCP/IP stack          │  │
│  └────────────────────────┘  │
└──────────────────────────────┘
```

Convenience functions `WithPolicy` and `WithAudit` adapt the
`PolicyChecker` and `AuditWriter` interfaces into hooks.

### Package layout

```
shim/
├── netstack_core.go   Netstack struct — user-space TCP/IP
├── netstack.go        NetstackOption + With* functions
├── policy.go          PolicyChecker interface
├── audit.go           AuditWriter interface + AuditEvent struct
├── wireguard.go       WireGuardEndpoint / WireGuardBind interfaces
└── internal/test/     Mock implementations for testing
```

---

## Interfaces

### PolicyChecker

```go
type PolicyChecker interface {
    Allow(identity string, dstIP net.IP, dstPort uint16) bool
}
```

Called before every connection (via `WithPolicy`). Return `false` to deny
the connection. If no policy is set, all connections are allowed.

### AuditWriter

```go
type AuditWriter interface {
    Write(event AuditEvent) error
}

type AuditEvent struct {
    Identity string `json:"identity"`
    SrcIP    string `json:"src_ip"`
    DstIP    string `json:"dst_ip"`
    DstPort  uint16 `json:"dst_port"`
    Protocol string `json:"protocol"`
    Verdict  string `json:"verdict"` // "allow" | "drop"
}
```

Receives every allow/drop decision (via `WithAudit`). Your implementation
might batch events and POST them to a control plane, write to a local log,
or feed an alerting pipeline.

### WireGuardBind

```go
type WireGuardBind interface {
    Write(packet []byte) error
    Read() ([]byte, error)
    Close() error
}
```

Minimal packet I/O interface that bridges gVisor's link endpoint to
wireguard-go's device bind.

---

## Usage

### 1. Install

```bash
go get github.com/alatticeio/lattice-shim
```

### 2. Simplest usage

```go
package main

import (
    "context"
    "fmt"

    "github.com/alatticeio/lattice-shim/shim"
)

func main() {
    // Create a user-space netstack — no policy, no audit.
    ns, err := shim.NewNetstack("10.100.0.1")
    if err != nil {
        panic(err)
    }
    defer ns.Close()

    // Dial through the user-space stack.
    conn, err := ns.DialContext(context.Background(), "tcp", "10.200.0.5:443")
    if err != nil {
        fmt.Println("dial failed:", err)
        return
    }
    defer conn.Close()

    // conn is a standard net.Conn — use it like any TCP connection.
    conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
}
```

### 3. With identity and hooks

```go
ns, _ := shim.NewNetstack("10.100.0.1",
    shim.WithIdentity("my-service/instance-3"),
    shim.WithBeforeDial(func(identity, network, addr string) error {
        if !isAllowed(addr) {
            return errors.New("connection denied")
        }
        return nil
    }),
    shim.WithAfterDial(func(identity, network, addr string, conn net.Conn, err error) {
        log.Printf("dial: id=%s network=%s addr=%s err=%v", identity, network, addr, err)
    }),
)
```

### 4. With PolicyChecker / AuditWriter interfaces

```go
// Implement the interfaces (or use nil for all-allow / no-audit).
type MyPolicy struct{}

func (p *MyPolicy) Allow(identity string, dstIP net.IP, dstPort uint16) bool {
    return dstPort == 443
}

type MyAudit struct{}

func (a *MyAudit) Write(ev shim.AuditEvent) error {
    log.Printf("AUDIT: identity=%s dst=%s:%d verdict=%s", ev.Identity, ev.DstIP, ev.DstPort, ev.Verdict)
    return nil
}

// Wire them up via convenience options.
ns, _ := shim.NewNetstack("10.100.0.1",
    shim.WithIdentity("sandbox:agent-1"),
    shim.WithPolicy(&MyPolicy{}),
    shim.WithAudit(&MyAudit{}),
)
```

### 5. With WireGuard integration

```go
ns, _ := shim.NewNetstack("10.100.0.1",
    shim.WithIdentity("sandbox:agent-1"),
    shim.WithPolicy(myPolicy),
    shim.WithAudit(myAudit),
)
defer ns.Close()

// Attach wireguard-go to the netstack channel endpoint:
ep := &shim.WireGuardEndpoint{
    Outbound: func(packet []byte) error {
        // Encrypted WG packet → raw UDP socket to peer.
        return wgSocket.Write(packet)
    },
    Inbound: func(packet []byte) error {
        // Decrypted packet from WG → inject into gVisor netstack.
        ns.Channel().InjectInbound(header.IPv4ProtocolNumber, packetBuf)
        return nil
    },
    Close: func() error {
        return wgSocket.Close()
    },
}
// Ready: traffic from ns.DialContext() goes through:
//   gVisor TCP/IP → channel → wireguard-go encrypt → UDP socket → peer
```

---

## API Reference

### Netstack

```go
type Netstack struct {
    Identity   string
    BeforeDial func(identity, network, addr string) error
    AfterDial  func(identity, network, addr string, conn net.Conn, err error)
}

func NewNetstack(localIP string, opts ...NetstackOption) (*Netstack, error)
func (ns *Netstack) DialContext(ctx context.Context, network, addr string) (net.Conn, error)
func (ns *Netstack) ListenTCP(addr string) (net.Listener, error)
func (ns *Netstack) Channel() *channel.Endpoint
func (ns *Netstack) Stack() *stack.Stack
func (ns *Netstack) Close() error
```

### Options

```go
func WithIdentity(id string) NetstackOption
func WithBeforeDial(fn func(identity, network, addr string) error) NetstackOption
func WithAfterDial(fn func(identity, network, addr string, conn net.Conn, err error)) NetstackOption
func WithPolicy(pc PolicyChecker) NetstackOption
func WithAudit(aw AuditWriter) NetstackOption
```

---

## Integrating into Lattice

The Lattice main repo integrates `lattice-shim` via a thin adapter layer
under `internal/agent/gvisor/`:

```
lattice/internal/agent/gvisor/
├── manager.go           # SandboxManager → creates Netstack for each sandbox
├── policy_adapter.go    # PolicyCache → shim.PolicyChecker adapter
├── audit_adapter.go     # AuditBatcher → shim.AuditWriter adapter
└── ...
```

### Adapter examples

**Policy adapter:**

```go
import "github.com/alatticeio/lattice-shim/shim"

type PolicyAdapter struct {
    cache     *sidecar.PolicyCache
    sandboxID string
}

func (a *PolicyAdapter) Allow(identity string, dstIP net.IP, dstPort uint16) bool {
    return a.cache.Query(a.sandboxID, dstIP, dstPort)
}
```

**Usage in manager.go:**

```go
ns, _ := shim.NewNetstack(agentIP,
    shim.WithIdentity("sandbox:"+sandboxID),
    shim.WithPolicy(&PolicyAdapter{cache: policyCache, sandboxID: sandboxID}),
    shim.WithAudit(&AuditAdapter{batcher: auditBatcher}),
)
```

### Dependency flow

```
lattice-shim (zero Lattice deps)
  ├─ gvisor.dev/gvisor
  └─ golang.zx2c4.com/wireguard

lattice/internal/agent/gvisor/ (Lattice main repo)
  ├─ github.com/alatticeio/lattice-shim
  ├─ lattice/internal/agent/sidecar   ← PolicyCache implementation
  ├─ lattice/internal/agent/audit     ← AuditBatcher implementation
  └─ ...
```

The shim stays pure: it does not know about Lattice CRDs, NATS, or
control-plane protocols. The adapter layer in the Lattice main repo
translates between Lattice concepts (PolicyCache, AuditBatcher) and
shim interfaces (PolicyChecker, AuditWriter).

---

## Integrating into other projects

Since `lattice-shim` has **zero Lattice-specific dependencies**, you can use
it in any Go project that needs:

- A user-space TCP/IP stack (gVisor) without root
- WireGuard encryption in user space
- Pluggable hooks for outbound connections
- Audit logging of allow/drop decisions

### Step-by-step

1. **Implement interfaces** (or use `nil` for all-allow / no-audit).
2. **Create the Netstack** with `shim.NewNetstack(localIP, opts...)`.
3. **Use `ns.DialContext()`** wherever you need a user-space TCP connection.

### Example use cases

| Use case | Hooks | Audit |
|---|---|---|
| AI agent sandbox | Allow-list of API endpoints | Batch → control plane |
| VPN client app | Allow-all (no BeforeDial) | Local log file |
| IoT device mesh | Identity-based allow-list | MQTT publish |
| Testing / CI | None | None |

---

## Build and test

```bash
go build ./shim
go test ./shim
go vet ./shim
```

The library imports only the Go standard library plus `gvisor.dev/gvisor`
and (optionally) `golang.zx2c4.com/wireguard`.

---

## Design principles

- **Zero Lattice deps.** The shim imports no Lattice packages. The Lattice
  main repo implements `PolicyChecker` and `AuditWriter` by adapting its
  own policy cache and audit batcher.
- **Interfaces, not frameworks.** The shim defines narrow interfaces and the
  caller injects concrete implementations.
- **Zero privilege.** The entire data path runs in user space — no TUN
  device, no `CAP_NET_ADMIN`, no root.
- **Standard `net.Conn`.** Connections returned by `DialContext` are ordinary
  `net.Conn` values, so all standard Go networking code works unchanged.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)
