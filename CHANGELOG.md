# Changelog

## Unreleased

- Add an unsigned, per-user Windows NSIS installer with Italian/English localization and a manual artifact workflow.
- Persist validated non-secret proxy workspace settings locally across app restarts, with an explicit reset action; ephemeral credentials and HTTPS inspection opt-in remain per-run.
- Add ordered Development-only response rules for host/path/method matching, bounded status/body replacement and visible applied-rule metadata.
- Add safe same-target replay for completed bodyless Development HTTP GET/HEAD captures without built-in credential headers.
- Add Development response breakpoints with timeout, final-status override and bounded UTF-8 body replacement.
- Add opt-in verified Development HTTPS inspection for persistent HTTP/1.1 and bounded multiplexed HTTP/2 exchanges.

- Add full-body literal UTF-8 search with progress, cancellation, overlapping matches and navigation to the matching raw offset.
- Add validated, paged JSON layout on disk, preserving number precision, duplicate keys and escapes; preparation is cancellable and shares the body storage budget.
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

This remains a desktop development preview. Installer signing, portable sessions, edit/session replay and advanced rule actions are not available yet.
