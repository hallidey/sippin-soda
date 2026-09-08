# Changelog

## Unreleased

- Add opaque CONNECT tunnels for HTTPS, with bounded lifetimes, live transport byte counts, cancellation and explicit tunnel status in the inspector.
- Verify early tunnel bytes, half-close, concurrency, invalid targets, loop prevention and end-to-end TLS certificate validation with local fixtures.
- Add a real explicit HTTP proxy with desktop Start/Stop, streaming forwarding, filtered metadata capture, request selection and native IPC updates.
- Bound retention and concurrent connections; handle timeouts, cancellation, upstream failures and self-routing.
- Add a local fixture server and HTTP integration tests.

- Establish the complete Sippin Soda product baseline and delivery backlog.
- Add the desktop foundation with Tauri, React and TypeScript.
- Introduce an independent Rust core with initial production policy and credential header redaction tests.
- Add navigation, theme preferences and an explicit empty traffic state.
- Configure native CI checks for Windows, macOS and Linux.

This is an HTTP development preview. Body recording, replay, TLS interception and installers are not available yet.
