# Changelog

## Unreleased

- Add opt-in HTTP response recording to temporary disk files, with 64 KiB text/hex pages, direct byte offsets and streaming gzip/deflate/Brotli decoding.
- Support full large responses without a per-response capture cap or the former fixed HTTP transfer lifetime; retain a configurable session disk budget and mark incomplete recordings explicitly without truncating forwarding.
- Verify 128 MiB capture and tail reads, live inspection, partial storage, cancellation, clear and compressed/empty bodies. Add 1800 KiB local JSON fixtures.
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

This is a desktop development preview. Request body inspection, body redaction, replay, TLS interception and installers are not available yet.
