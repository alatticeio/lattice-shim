# Lattice 流量注入方式设计

## 背景

`lattice-shim` 已有 gVisor 用户态 TCP/IP 栈（`Netstack`），提供 `DialContext` / `ListenTCP`。
现在需要把不同环境的流量"灌"进这个 netstack，让它能经过 wireguard-go → ICE/LRP 到达远端。

## 两类场景

| 场景 | 说明 | 流量入口 |
|------|------|----------|
| **Agent 沙箱** | Agent 进程运行在 gVisor (runsc) 内部 | 无需注入，Agent 在 netstack 里 |
| **宿主机接入** | 开发者笔记本/服务器/手机要连 mesh | 需要把宿主机流量导入 gVisor netstack |

Agent 沙箱场景已被 design doc 覆盖。本次聚焦**宿主机接入**。

## 可选方案矩阵

| 方案 | 特权 | 透明度 | 实现复杂度 | 最佳场景 |
|------|------|--------|-----------|----------|
| **A. SOCKS5 代理** | 零 | 需程序配合 proxy config | 低 | 容器、macOS 开发、CI |
| **B. HTTP CONNECT 代理** | 零 | 仅 HTTP 工具配合 | 极低 | 仅 HTTP 流量的简单场景 |
| **C. TUN 设备** | CAP_NET_ADMIN | 全局透明 | 中 | Linux 服务器、路由节点 |
| **D. LD_PRELOAD 劫持** | 零 | 对动态链接程序透明 | 中 | 无 root 时的 CLI 工具 |
| **E. Android VPN API** | 零 (系统 API) | 全局透明 | 高 | Android 手机 |
| **F. iOS Network Extension** | 零 (系统 API) | 全局透明 | 高 | iPhone/iPad |
| **G. iptables/nftables 重定向** | root | 全局透明 + 选择性 | 中 | 指定进程/UID 的流量劫持 |

## 推荐路线图

### Phase 1: SOCKS5 + gVisor（已实现）

内核：`net.Listener` 接 SOCKS5 请求 → 解析目标地址 → 走 `Netstack.DialContext`。

```
宿主机应用
  │ $ curl --socks5 127.0.0.1:1080 http://10.100.0.5:8080
  │ $ export ALL_PROXY=socks5://127.0.0.1:1080
  ▼
shim/socks5.go   ← SOCKS5 server on 127.0.0.1:1080
  │
  ▼
Netstack.DialContext()   ← gVisor user-space TCP/IP
  │
  ▼
wireguard-go → ICE/LRP → 远端
```

实现文件：
- `shim/socks5.go` — SOCKS5 server，接收标准 SOCKS5 请求（RFC 1928）
- `shim/socks5_test.go` — 集成测试

不做 HTTP CONNECT（SOCKS5 已经覆盖所有 TCP）

### Phase 2: TUN 设备（Linux，需要 root）

```
宿主机应用
  │ $ ping 10.100.0.5    ← 全部流量透明走 mesh
  │ $ ssh 10.100.0.5
  ▼
内核路由表
  │ 10.100.0.0/16 dev wf0
  ▼
wf0 TUN 设备
  │ read IP packets
  ▼
gVisor netstack (InjectInbound) → wireguard-go → 远端
```

需要 CAP_NET_ADMIN。适合路由节点、Linux 服务器。

### Phase 3: 移动端（后续版本）

Android VPN API / iOS NEPacketTunnelProvider，平台相关代码在独立 repo 或 lattice 主 repo 中。

## 可选的 AB 问题

1. **SOCKS5 是否区分身份**：同一台机器的不同用户/进程连 SOCKS5 时，是否要区分 Identity（用于策略判定）？

2. **TUN 模式是否要作为 lattice-shim 的一部分**：还是放在 lattice 主 repo？shim 只做纯用户态，TUN 涉及内核配置更适合主 repo。

3. **移动端优先级**：Android/iOS 现在做，还是等 Phase 1-2 验证完再做？
