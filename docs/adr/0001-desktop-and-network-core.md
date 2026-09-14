# ADR 0001: desktop shell and network core

Status: provisional. Rust is selected for the foundation; the network decision must be revisited after the HTTP/TLS spike. A reproducible Rust pass-through/TLS baseline now exists, but cross-platform repetitions and a comparable C++ run remain outstanding.

## Context

Sippin Soda needs an independent network engine, a local desktop UI, bounded resource use and cross-platform maintenance. The product specification requires an explicit Rust/C++ comparison before committing to the network implementation.

| Criterion | Rust | C++ |
| --- | --- | --- |
| Memory/concurrency safety | Ownership and type system constrain many classes of errors; unsafe and dependency code still need review | Requires stronger manual lifetime discipline, sanitizers and review |
| Networking | Candidate stack: Tokio, Hyper, Rustls; protocol coverage needs a spike | Candidate stack: Boost.Asio/Beast and OpenSSL; protocol coverage needs a spike |
| Desktop boundary | Direct Tauri integration and shared crate with CLI | Requires FFI or a sidecar protocol with Tauri |
| Toolchain | Cargo plus platform SDKs; Windows requires a linker | CMake/toolchain plus platform SDKs; library distribution needs care |
| Maintenance | One core language with Tauri, centralized dependency resolution | Strong ecosystem but additional FFI/build/ownership work |
| Performance | Must measure forwarding, streaming, memory and TLS overhead | Must measure the same workload; no assumed winner |

## Decision for this PR

Use React + TypeScript in a Tauri 2 shell. Put engine contracts and policies in `crates/engine` with no UI dependency. Use Rust provisionally to avoid introducing an FFI boundary before there is evidence it is needed. Do not add a hosted API or cloud store.

The HTTP spike now uses Tokio + Hyper in the independent engine crate. It has an explicit loopback listener, streaming forwarding, bounded metadata capture and cancellation. Local integration fixtures verify real transfers, failure paths and lifecycle. Effective HTTP and CONNECT target hosts are classified with validated Development/Production rules; unlisted hosts remain Unknown and active-operation authorization fails closed. A consent-based local CA can be generated into operating-system credential storage and its public certificate exported. The engine issues ephemeral host-scoped leaves only for Development destinations. A readiness gate requires opt-in, current CA identity, a selected client-profile identity and a successful client trust handshake. The desktop authenticates one profile with an ephemeral proxy credential whose token is stored only as a digest. A combined backend preflight derives identity from live engine state and becomes ready only when proxy, profile, CA and proof match. After a separate per-run opt-in, ready Development CONNECT routes terminate downstream TLS and open separately verified upstream TLS using the platform verifier; all other routes remain opaque. The listener parses persistent inner HTTP/1.1 requests, pins each to the CONNECT authority and creates an independent capture through the bounded metadata, body-budget and JSON-redaction pipeline. Listener fixtures cover routing denial and two safe exchanges on one TLS connection, while isolated bridge fixtures cover untrusted chains, hostname mismatch and bidirectional transport. HTTP/2 and session persistence remain unimplemented.

## Required validation before accepting the network decision

1. HTTP spike implemented: local upstream fixtures, streaming byte forwarding and cancellation. Desktop Start/Stop, native IPC events and real 200/500/slow captures verified on Windows. This is functional evidence, not a performance benchmark.
2. Test CONNECT pass-through separately from TLS interception; validate upstream trust and failure behavior.
3. Record hardware, concurrency, payload size, throughput, p50/p95 overhead and peak memory. The harness and initial Windows baseline are documented in [TLS transport benchmark](../benchmarks/TLS_TRANSPORT.md); repeat runs and other platforms remain pending.
4. Evaluate Hyper/Rustls limitations against the protocol roadmap and compare a C++ alternative where gaps matter.
5. Decide library vs sidecar isolation, crash recovery and IPC backpressure in a follow-up ADR.

## References

- [Tauri architecture and setup](https://tauri.app/start/)
- [Tauri platform prerequisites](https://tauri.app/start/prerequisites/)
- [Hyper 1 guides](https://hyper.rs/guides/1/)

These references describe candidate technologies; they are not evidence of a completed Sippin Soda benchmark.
