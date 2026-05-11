# lattice-shim

Zero-privilege bridge between gVisor netstack and wireguard-go, with
pluggable policy checking and audit writing. This library has **no
dependency** on Lattice CRDs, NATS, or any Lattice control-plane
components—it can be used in any project that needs user-space WireGuard
attached to a user-space TCP/IP stack.

## Design

See `docs/design/2026-05-11-agent-sandbox-and-ecosystem-design.md` section
2.1.2 for the full design context.

## Package layout

```
shim/
├── policy.go      PolicyChecker interface
├── audit.go       AuditWriter interface + AuditEvent struct
├── netstack.go    NetstackBridge — gVisor netstack → wireguard-go
└── wireguard.go   WireGuardBind — minimal bind interface
```

## Principles

- **Zero Lattice deps.** The shim imports only the Go standard library
  plus `gvisor.dev/gvisor` and `golang.zx2c4.com/wireguard`. The main
  Lattice repo implements `PolicyChecker` and `AuditWriter` by adapting
  its own policy cache and audit batcher.
- **Interfaces, not frameworks.** The shim defines narrow interfaces
  (`PolicyChecker`, `AuditWriter`, `WireGuardBind`) and the caller
  injects concrete implementations.
- **Zero privilege.** The bridge works entirely in user space—no TUN
  device, no `CAP_NET_ADMIN`, no root.

## Build

```bash
go build ./shim
go test ./shim
```

## License

Apache 2.0
