# Sippin Soda

**The programmable network layer for local development.**

Sippin Soda is not an API client with a proxy attached. It is a programmable development network layer that sits between an application and the services it communicates with.

An open-source desktop project for Windows, macOS and Linux, designed to observe, intercept, modify, replay, mock and route application traffic. Local-first, with no account or hosted backend required.

## Current state

**Desktop proxy development preview.** The Tauri desktop app starts/stops a real loopback HTTP proxy backed by an independent Rust engine. Traffic shows real HTTP metadata and opaque CONNECT tunnels for HTTPS. Effective destination hosts are classified as Development, Production or Unknown using validated exact/wildcard rules; loopback is Development by default and unlisted hosts fail closed as Unknown for future active operations. Optional response recording streams decoded bytes to temporary files with paged text/hex/JSON inspection. Opt-in JSON request inspection buffers at most 1 MiB, forwards the original bytes unchanged, redacts sensitive keys plus configurable JSON Pointer paths, and writes only the redacted copy to disk; other request formats are explicitly unavailable. A shared session disk budget bounds storage and each inspector read is at most 64 KiB. Completed bodies can be explicitly exported through a native save dialog after a safety preview; unredacted responses require an additional acknowledgement. Response bodies remain unredacted and body files are not encrypted at rest. TLS interception, replay, modification and portable sessions are not implemented yet. No CA is installed and no system proxy setting is changed.

Follow the [local HTTP walkthrough](docs/HTTP_PROXY.md) to send traffic through Sippin Soda to the included fixture server.

## Development

Install Node.js 24 and the [Tauri platform prerequisites](https://tauri.app/start/prerequisites/) including Rust and a native compiler/linker. On Windows this includes Microsoft C++ Build Tools and WebView2.

```sh
npm ci
npm run desktop
```

The npm desktop/test commands also recognize an optional local Rust installation under `.tools/cargo` and `.tools/rustup`, without modifying the system PATH. Otherwise they use the normal installed Rust toolchain. Stop an existing `npm run dev` preview before starting `npm run desktop`, since both use port 1420.

`npm run dev` previews the UI in a browser for development only; capture controls require the native app. `npm run build` typechecks and builds the frontend. `cargo test -p sippin-soda-engine` runs policy and real HTTP integration tests. `npm run tauri -- build --no-bundle` compiles the desktop application; installer packaging/signing is a later milestone.

## Structure

- `src/`: desktop frontend and typed IPC consumer.
- `src-tauri/`: native application shell and commands.
- `crates/engine/`: independent engine contracts and initial policies.
- [Master specification](MASTER_PROMPT.md): complete product requirements.
- [Delivery backlog](docs/BACKLOG.md): scope and implementation state.
- [ADR 0001](docs/adr/0001-desktop-and-network-core.md): provisional Rust/C++ decision and required network spike.

Repository owner and PR operator: **Alessandro-Fedele**. Licensed under the [MIT License](LICENSE).
