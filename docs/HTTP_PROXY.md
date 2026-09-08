# HTTP and CONNECT proxy development preview

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

- HTTP forwarding uses absolute-form request URLs. HTTPS uses CONNECT with an authority-only `host:port` target and no request body. The upstream TCP connection is established before acknowledging CONNECT. Direct HTTP Upgrade requests return 501.
- Upstream request and response bodies stream with Hyper backpressure. No payload bytes are retained, indexed or sent to the webview. Body inspection will be a separate increment.
- Up to 200 captures; oldest captures are evicted with a visible count. Each side records up to 48 header entries, with names capped at 128 characters and values at 256. Target host/path are capped at 256/1024 characters. Header lists may therefore be incomplete.
- Entire query strings and non-allowlisted header values are redacted in captures; originals still reach the upstream. URL paths remain visible and may contain sensitive data. This is not complete sensitive-data redaction.
- At most 64 downstream connections, including upgraded CONNECT tunnels. Excess connections are closed and counted. Each accepted HTTP connection has one request; HTTP client keep-alive reuse is deliberately disabled for this spike. A CONNECT tunnel can carry multiple encrypted requests.
- 30 seconds to receive upstream HTTP headers or establish the CONNECT destination; HTTP connection lifetime is bounded to approximately 31 seconds, including slow client headers and response streaming. CONNECT tunnels have a separate 300-second lifetime after upgrade (not an idle timeout). Long streams may be interrupted and marked as errors. Engine configuration allows a tunnel lifetime up to 3600 seconds; the desktop currently uses 300.
- Upstream redirects are returned to the client, not followed by the engine. If the client follows them, those are separate requests.
- Upstream failures yield 502; upstream-header timeout yields 504; self-routing detected after DNS resolution yields 508. No replay, mutation or fault injection is enabled.
- Transport completion means the proxy consumed the upstream body; it cannot prove that the receiving application processed it.
- Frontend updates use native IPC invalidation events capped at four per second, followed by bounded snapshots. Nothing is persisted to disk.

## Validation

Run `cargo test -p sippin-soda-engine` for real local TCP/HTTP/TLS fixtures. They cover forwarding, header rewriting/redaction, unsupported targets, loops, upstream errors, timeouts, stopping, port reuse, retention and large responses. CONNECT tests additionally verify early bytes, half-close, live counts, tracked concurrency, bounded lifetime and HTTPS with trusted/untrusted test certificates. Test certificates are ephemeral and trusted only by the test client; they never enter the OS trust store. See ADR 0001 for the remaining TLS interception and performance decision gates.

## HTTPS pass-through

With the proxy running, send a request to an HTTPS service you intend to test:

```sh
curl --noproxy "" --proxy http://127.0.0.1:8080 https://example.com/
```

Keep the proxy URL as `http://`: CONNECT creates the tunnel and the client then negotiates TLS directly with the destination. Use your development server's CA with curl's `--cacert` when needed; the proxy neither trusts certificates on your behalf nor disables client verification.

The UI shows `CONNECT example.com:443` and `200 · Tunnel`. This 200 means the TCP tunnel opened, **not** that the HTTPS API returned 200. Paths, query strings, inner headers, bodies and inner statuses are not visible. Recorded headers belong only to the CONNECT negotiation and use the usual redaction rules. Byte counts measure forwarded opaque transport bytes in each direction, including TLS handshakes; payload bytes are never retained. TLS alerts and certificate failures are opaque too, so the capture cannot diagnose the client's TLS validation result. Stop closes both ends of active tunnels. No certificate authority or TLS interception is enabled.
