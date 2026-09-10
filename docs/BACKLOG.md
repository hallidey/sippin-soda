# Delivery backlog

The authoritative product baseline is [MASTER_PROMPT.md](../MASTER_PROMPT.md). This file tracks implementation, not product ambition.

| Requirement | Target | Current state | Exit evidence |
| --- | --- | --- | --- |
| Desktop foundation | v0.1 | Tauri/React scaffold, theme settings, honest empty states | UI build; CI native compilation |
| F01 Observe | v0.1 | HTTP proxy, CONNECT, bounded metadata, disk-backed response inspection and redacted JSON request inspection; TLS inspection pending | Real HTTP/TCP/TLS fixtures plus request-redaction, 128 MiB response/tail and compressed body tests |
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
| F16 TLS/production safety | v0.1 onward | Pure active-operation policy, effective-host classifier, visible safety class and opaque CONNECT; no TLS interception yet | Classification/overlap and pass-through TLS fixtures implemented; route revalidation and interception fixtures pending |

## Next implementation PR

Effective HTTP/CONNECT destinations now have validated Development, Production and Unknown classification based on the actual target rather than request headers; ambiguous policies fail startup and the class stays visible per capture. Next, prepare consent-based CA/TLS inspection separately from opaque CONNECT transport, revalidate redirects/routes as those capabilities arrive, and complete the benchmark gates in ADR 0001 before expanding into interception. Portable session export remains a later F11 slice.
