# Delivery backlog

The authoritative product baseline is [MASTER_PROMPT.md](../MASTER_PROMPT.md). This file tracks implementation, not product ambition.

| Requirement | Target | Current state | Exit evidence |
| --- | --- | --- | --- |
| Desktop foundation | v0.1 | Tauri/React scaffold, theme settings, honest empty states | UI build; CI native compilation |
| F01 Observe | v0.1 | HTTP proxy, CONNECT, bounded metadata, disk-backed response inspection and redacted JSON request inspection for HTTP and persistent HTTP/1 HTTPS tunnels | Real HTTP/TCP/TLS fixtures plus request-redaction, 128 MiB response/tail and compressed body tests |
| F02 Intercept/modify | v0.1 | Explicit Development-only response breakpoint with 15-second fail-safe, controlled final-status replacement, and bounded UTF-8 body/Content-Type replacement | Pause response, return a mock JSON error, continue |
| F03 Replay | v0.1 / v0.3 sessions | Same-target replay for completed bodyless Development HTTP GET/HEAD captures; HTTPS, request bodies, editing and session replay pending | Replay targets local fixture without forwarding credentials; Production fails closed |
| F04 Rules | v0.1 / v0.3 advanced | Ordered, persistent Development-only response rules match exact/wildcard host, path prefix and method to replace a body-compatible final status plus an optional bounded UTF-8 body/Content-Type; delays and richer conditions pending | First matching mock-error rule survives app restart; Production remains unchanged |
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
| F16 TLS/production safety | v0.1 onward | Active-operation policy, effective-host classifier, visible safety class, authenticated client routing, combined live preflight, default opaque CONNECT, consent-based local CA generation/export, bounded profile-specific client trust check, opt-in Development-only TLS listener, platform upstream verification, explicit ALPN, persistent HTTP/1 and bounded HTTP/2 HTTPS capture, and reproducible benchmark | Classification/overlap, CA generation, host/SAN validation, authenticated pass-through, trust-check lifecycle, live route revalidation, TLS listener integration, ALPN rejection, bounded/redacted HTTP/1 and multiplexed HTTP/2 fixtures implemented; cross-platform/C++ comparison and OS trust automation pending |

## Next implementation PR

The authenticated profile and live trust preflight gate an explicitly enabled Development-only CONNECT TLS listener. Negotiated HTTP/1 requests and bounded HTTP/2 streams each receive an independent redacted capture with the upstream authority fixed to CONNECT. Development response breakpoints and persistent ordered rules share bounded status/body replacement, while safe replay repeats completed bodyless HTTP GET/HEAD captures against the same target. Next, add an explicitly bounded delay action to response rules without introducing request-side effects. Do not introduce silent trust-store mutation, credential forwarding to a new host or any verification bypass. Portable session export remains a later F11 slice.
