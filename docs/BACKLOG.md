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
| F16 TLS/production safety | v0.1 onward | Active-operation policy, effective-host classifier, visible safety class, optional authenticated client routing, opaque CONNECT, consent-based local CA generation/export, bounded profile-specific client trust check, Development-only host certificates, strictly verified/flushed TLS bridge, readiness gate and reproducible benchmark; app interception remains off | Classification/overlap, CA generation, host/SAN validation, authenticated pass-through, trust-check lifecycle, profile/CA proof invalidation and Windows baseline fixtures implemented; cross-platform/C++ comparison, TLS listener integration, OS trust automation and route revalidation pending |

## Next implementation PR

Settings now offers named local client profiles and a single-use, 60-second loopback workflow whose proof is bound to the selected profile. A proxy run can optionally authenticate that profile with an ephemeral credential; unauthenticated HTTP and CONNECT requests fail before upstream access, while accepted captures carry the profile ID. Next, feed that authenticated ID into the readiness gate and integrate an explicitly enabled, Development-only CONNECT interception route while retaining opaque pass-through for every other case. Repeat the benchmark on Windows/macOS/Linux; a comparable C++ workload remains required before finalizing ADR 0001. Do not introduce silent trust-store mutation or any verification bypass. Portable session export remains a later F11 slice.
