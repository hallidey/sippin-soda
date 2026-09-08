# Contributing

Read the master specification, backlog and ADRs before making changes. Keep the engine independent of the desktop UI. Use `codex/` branches for agent-assisted work and small reviewable pull requests. Repository and PR operations for this workspace must use the **Alessandro-Fedele** GitHub account.

Run `npm run build`, `cargo fmt --all -- --check`, `cargo test -p sippin-soda-engine` and `cargo clippy --workspace --all-targets -- -D warnings`. Native CI must pass on Windows, macOS and Linux. Never commit tokens, private certificates, session payloads or local tool installations. Do not show synthetic requests as live captures.
