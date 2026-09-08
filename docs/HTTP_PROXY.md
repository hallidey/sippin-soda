# HTTP proxy development preview

The desktop app now starts and stops a real, explicit HTTP/1 proxy. It binds only to IPv4 loopback. Default port: 8080; choose another port before starting if occupied. Starting the app does not start the proxy or change system proxy settings.

## Try the complete local path

1. Start `npm run desktop` using the toolchain in the README.
2. In a separate terminal run `node examples/http-fixture.mjs`.
3. In the desktop app choose **Start proxy**.
4. Send a request through the proxy:

```sh
curl --noproxy "" --proxy http://127.0.0.1:8080 http://127.0.0.1:9090/health
curl --noproxy "" --proxy http://127.0.0.1:8080 http://127.0.0.1:9090/error
curl --noproxy "" --proxy http://127.0.0.1:8080 http://127.0.0.1:9090/slow
```

On Windows PowerShell use `curl.exe` if `curl` is an alias. `--noproxy ""` prevents a client's localhost bypass from skipping the proxy. Select a request to view request/response headers, status, timing and byte counts. The fixture is a real HTTP server; the application does not manufacture traffic rows.

**Stop proxy** stops accepting connections and cancels active transfers. Closing the desktop app stops the engine. **Clear** removes only the in-memory capture list and does not stop forwarding.

## Scope and bounds

- HTTP absolute-form request URLs only. CONNECT/HTTPS and protocol upgrades return 501. This milestone does not install a CA or provide HTTPS pass-through yet.
- Upstream request and response bodies stream with Hyper backpressure. No payload bytes are retained, indexed or sent to the webview. Body inspection will be a separate increment.
- Up to 200 captures; oldest captures are evicted with a visible count. Each side records up to 48 header entries, with names capped at 128 characters and values at 256. Target host/path are capped at 256/1024 characters. Header lists may therefore be incomplete.
- Entire query strings and non-allowlisted header values are redacted in captures; originals still reach the upstream. URL paths remain visible and may contain sensitive data. This is not complete sensitive-data redaction.
- At most 64 downstream connections. Excess connections are closed and counted. Each accepted connection has one request; client keep-alive reuse is deliberately disabled for this spike.
- 30 seconds to receive upstream headers; connection lifetime is bounded to approximately 31 seconds, including slow client headers and response streaming. Long streams may be interrupted and marked as errors.
- Upstream redirects are returned to the client, not followed by the engine. If the client follows them, those are separate requests.
- Upstream failures yield 502; upstream-header timeout yields 504; self-routing detected after DNS resolution yields 508. No replay, mutation or fault injection is enabled.
- Transport completion means the proxy consumed the upstream body; it cannot prove that the receiving application processed it.
- Frontend updates use native IPC invalidation events capped at four per second, followed by bounded snapshots. Nothing is persisted to disk.

## Validation

Run `cargo test -p sippin-soda-engine` for real local TCP/HTTP fixtures. They cover forwarding, header rewriting/redaction, unsupported targets, loops, upstream errors, timeouts, stopping, port reuse, retention and large responses. See ADR 0001 for the remaining TLS and performance decision gates.
