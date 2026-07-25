# MCP Transport Coverage Matrix

| Transport Type | crucible trace proxy | crucible scan | eBPF sidecar (Linux) |
|---|---|---|---|
| Streamable HTTP | ✅ Full intercept | ✅ Scannable | ✅ Observable |
| HTTP+SSE (deprecated) | ✅ Full intercept | ✅ Scannable | ✅ Observable |
| stdio (subprocess) | ❌ Invisible to proxy | ❌ Not directly scannable | ✅ Observable via execve |
| Custom TCP/IPC | ⚠️ Depends | ❌ Not scannable | ⚠️ Partial |

## Covering stdio transport

If your MCP server uses stdio, the trace proxy cannot intercept it.
Options:
1. eBPF sidecar (Linux only) — monitors the execve syscall
2. Wrap the stdio MCP server in a thin HTTP adapter
3. Use crucible scan with manual SSRF probing

## Detecting your transport type
crucible mcp-scan --target http://localhost:3000 --show-transport
