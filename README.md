# Sippin Soda

**The programmable network layer for local development.**

Sippin Soda is not an API client with a proxy attached. It is a programmable development network layer that sits between an application and the services it communicates with.

An open-source desktop project for Windows, macOS and Linux, designed to observe, intercept, modify, replay, mock and route application traffic. Local-first, with no account or hosted backend required.

## Current state

Early foundation, **not a working proxy yet**. This first increment contains the Tauri + React + TypeScript desktop structure, a UI-independent Rust engine crate, initial safety/header-redaction policies, workspace navigation and theme preferences. All traffic screens start empty; capture is disabled until the real networking milestone. No CA is installed and no system proxy setting is changed.

## Development

Install Node.js 24 and the [Tauri platform prerequisites](https://tauri.app/start/prerequisites/) including Rust and a native compiler/linker. On Windows this includes Microsoft C++ Build Tools and WebView2.

```sh
npm ci
npm run desktop
```

`npm run dev` previews the UI in a browser for development only; the product is a native desktop app. `npm run build` typechecks and builds the frontend. `cargo test -p sippin-soda-engine` checks the initial core policies. `npm run tauri -- build --no-bundle` compiles the desktop application; installer packaging/signing is a later milestone.

## Structure

- `src/`: desktop frontend and typed IPC consumer.
- `src-tauri/`: native application shell and commands.
- `crates/engine/`: independent engine contracts and initial policies.
- [Master specification](MASTER_PROMPT.md): complete product requirements.
- [Delivery backlog](docs/BACKLOG.md): scope and implementation state.
- [ADR 0001](docs/adr/0001-desktop-and-network-core.md): provisional Rust/C++ decision and required network spike.

Repository owner and PR operator: **Alessandro-Fedele**. Licensed under the [MIT License](LICENSE).
