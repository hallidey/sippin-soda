# ADR 0001: desktop shell and network core

Status: provisional. Rust is selected for the foundation; the network decision must be revisited after the HTTP/TLS spike. No comparative benchmark has been run yet.

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

The current engine only exposes honest startup status and initial pure policy functions. It does not open a network listener, install a certificate or change system proxy settings. Session/body/query redaction and destination classification remain unimplemented.

## Required validation before accepting the network decision

1. Implement an explicit HTTP proxy spike with local upstream fixtures and streaming cancellation.
2. Test CONNECT pass-through separately from TLS interception; validate upstream trust and failure behavior.
3. Record hardware, concurrency, payload size, throughput, p50/p95 overhead and peak memory.
4. Evaluate Hyper/Rustls limitations against the protocol roadmap and compare a C++ alternative where gaps matter.
5. Decide library vs sidecar isolation, crash recovery and IPC backpressure in a follow-up ADR.

## References

- [Tauri architecture and setup](https://tauri.app/start/)
- [Tauri platform prerequisites](https://tauri.app/start/prerequisites/)
- [Hyper 1 guides](https://hyper.rs/guides/1/)

These references describe candidate technologies; they are not evidence of a completed Sippin Soda benchmark.
