# Delivery backlog

The authoritative product baseline is [MASTER_PROMPT.md](../MASTER_PROMPT.md). This file tracks implementation, not product ambition.

| Requirement | Target | Current state | Exit evidence |
| --- | --- | --- | --- |
| Desktop foundation | v0.1 | Tauri/React scaffold, theme settings, honest empty states | UI build; CI native compilation |
| F01 Observe | v0.1 | HTTP proxy, CONNECT, bounded metadata, disk-backed response inspection and redacted JSON request inspection for HTTP and persistent HTTP/1 HTTPS tunnels | Real HTTP/TCP/TLS fixtures plus request-redaction, 128 MiB response/tail and compressed body tests |
| F02 Intercept/modify | v0.1 | Planned | Pause response, change 200 to 500, continue |
| F03 Replay | v0.1 / v0.3 sessions | Planned | Replay targets local fixture; cancellation and ordering |
| F04 Rules | v0.1 / v0.3 advanced | Planned | Delay/status rule survives restart |
| F05 Chaos | v0.3 | Planned | Seeded faults and bounded scope |
| F06 Mocks | v0.2 / future stateful | Planned | Conditional match and Record → Mock |
| F07 Routing | v0.2 | Planned | LOCAL/DEV/TEST/MOCK fixture routing |
| F08 Environments/auth | v0.2 / future advanced | Planned | Host-bound credentials and safe environment switch |
| F09 Diff | v0.3 | Planned | Structural and original/modified comparison |
| F10 Contracts/discovery | v0.4 | Planned | Schema diagnostics, export and CI exit codes |
| F11 Sessions/redaction | v0.1 / v0.3 portable | Bounded memory captures, query/header filtering, redacted JSON request inspection and explicit body export safety preview; session persistence/export pending | Retention and credential filtering integration tests |
| F12 Client/collections | v0.2 / v0.3 | Planned | Compose/run/save request and generated test |
| F13 Scenarios | v0.3 | Planned | Atomic activation/reset with visible conflicts |
| F14 Protocol extensions | Future | Planned | Per-protocol capability matrix and fixtures |
| F15 CLI/plugins | v0.4 / future | Planned | Shared policy semantics; headless contract checks |
| F16 TLS/production safety | v0.1 onward | Active-operation policy, effective-host classifier, visible safety class, authenticated client routing, combined live preflight, default opaque CONNECT, consent-based local CA generation/export, bounded profile-specific client trust check, opt-in Development-only TLS listener, platform upstream verification, persistent HTTP/1 HTTPS capture and reproducible benchmark | Classification/overlap, CA generation, host/SAN validation, authenticated pass-through, trust-check lifecycle, live route revalidation, TLS listener integration, bounded/redacted persistent HTTP/1 capture and Windows baseline fixtures implemented; HTTP/2, cross-platform/C++ comparison and OS trust automation pending |

## Next implementation PR

The authenticated profile and live trust preflight now gate an explicitly enabled Development-only CONNECT TLS listener. The desktop uses platform certificate verification upstream, issues host-specific leaves only after route revalidation and retains opaque pass-through for Production, Unknown, non-ready and opted-out cases. Persistent HTTP/1 requests reuse one verified TLS connection and each receives an independent bounded/redacted capture with the upstream authority fixed to CONNECT. Next, define explicit ALPN behavior and evaluate bounded HTTP/2 capture without weakening destination or resource controls. Repeat the benchmark on Windows/macOS/Linux; a comparable C++ workload remains required before finalizing ADR 0001. Do not introduce silent trust-store mutation or any verification bypass. Portable session export remains a later F11 slice.
