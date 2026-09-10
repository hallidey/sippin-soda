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

**Stop proxy** stops accepting connections and cancels active transfers, retaining captures for inspection. Normal desktop exit stops the engine and clears captures. **Clear** removes metadata and temporary body files and cancels their recording, without stopping forwarding.

## Scope and bounds

- HTTP forwarding uses absolute-form request URLs. HTTPS uses CONNECT with an authority-only `host:port` target and no request body. The upstream TCP connection is established before acknowledging CONNECT. Direct HTTP Upgrade requests return 501.
- Upstream request and response bodies stream with backpressure. Optional HTTP response recording uses a bounded 64 KiB pipe and disk writer, with an additional bounded decoder buffer. A slow disk may slow forwarding, but cannot cause an unbounded queue. Opt-in request inspection copies JSON bodies into a buffer capped at 1 MiB while forwarding original frames unchanged, recursively replaces built-in sensitive keys, applies up to 64 additional JSON Pointer paths, and writes only the redacted representation. Non-JSON, invalid and oversized request bodies are explicitly unavailable and never written by request inspection. The frontend only receives requested pages, never a whole stored body.
- Up to 200 captures; oldest captures are evicted with a visible count. Each side records up to 48 header entries, with names capped at 128 characters and values at 256. Target host/path are capped at 256/1024 characters. Header lists may therefore be incomplete.
- Entire query strings and non-allowlisted header values are redacted in captures; originals still reach the upstream. URL paths remain visible and may contain sensitive data. This is not complete sensitive-data redaction.
- The effective HTTP URL or CONNECT authority host is classified as Development, Production or Unknown. Loopback is Development by default. Up to 128 exact or leading-wildcard (`*.example.com`) rules may be configured for each explicit class; overlapping Development/Production patterns prevent startup. A request `Host` header cannot override the absolute proxy target used for classification. Observation remains allowed for every class, while the shared policy API rejects replay, modification and fault injection for Production and Unknown destinations.
- At most 64 downstream connections, including upgraded CONNECT tunnels. Excess connections are closed and counted. Each accepted HTTP connection has one request; HTTP client keep-alive reuse is deliberately disabled for this spike. A CONNECT tunnel can carry multiple encrypted requests.
- 30 seconds for client HTTP headers and for receiving upstream HTTP headers or establishing CONNECT. HTTP response streaming no longer has a fixed total lifetime: a large/slow response can complete beyond 31 seconds. Idle response connections also remain open until upstream/client close or Stop; they occupy the shared 64-connection budget. CONNECT tunnels retain their separate 300-second lifetime after upgrade (not an idle timeout), configurable in the engine up to 3600 seconds.
- Upstream redirects are returned to the client, not followed by the engine. If the client follows them, those are separate requests.
- Upstream failures yield 502; upstream-header timeout yields 504; self-routing detected after DNS resolution yields 508. No replay, mutation or fault injection is enabled.
- Transport completion means the proxy consumed the upstream body; it cannot prove that the receiving application processed it.
- Metadata updates use native IPC invalidation events capped at four per second, followed by bounded snapshots. A selected recording body is read at most once per second until completion; page reads are separately bounded to 64 KiB. Only opt-in response bodies and redacted JSON request copies reach temporary disk files.

## Large HTTP responses

Before Start, enable **Record HTTP bodies** and choose the session disk budget (10 GiB by default, configurable from 1 to 1024 GiB in the desktop). There is no fixed per-response size cap. A response around 1800 KB is fully supported; the integration suite additionally checks the end of a 128 MiB response. JSON request inspection has a separate 1 MiB safety limit because redaction must complete before persistence. This is a functional large-file test, not a measured peak-memory benchmark.

Additional request redactions use RFC 6901-style JSON Pointers, one per line or comma-separated. For example, `/customer/email` redacts one nested value and `/items/*/cardNumber` redacts the field in every array item. `*` is Sippin Soda's wildcard extension for object members or array elements; `~1` addresses a literal `/` and `~0` a literal `~`. Invalid paths prevent the proxy from starting. These paths add to the built-in case-insensitive sensitive-key policy and cannot disable it.

```sh
curl --noproxy "" --proxy http://127.0.0.1:8080 http://127.0.0.1:9090/large --output large.json
curl --noproxy "" --proxy http://127.0.0.1:8080 --compressed http://127.0.0.1:9090/large-gzip --output large-decoded.json
```

Both fixtures contain a 1800 KiB string plus JSON framing and an `END-OF-LARGE-RESPONSE` marker. Open **Response → Response body**, then **Last** to see the marker. Use Previous/Next or a byte offset to read any portion of the body. UTF-8 text is displayed a page at a time; Hex preserves exact bytes. Characters split across a page boundary may show replacement characters in text view.

### Search and JSON layout

**Find in full body** searches original decoded bytes, not only the visible page. Matching is literal, case-sensitive UTF-8 (1–4096 query bytes); it does not interpret regexes, JSON escapes or JSON paths. Find from start begins at byte zero; Find next includes overlapping matches. A match opens its raw byte offset and highlights the matching text. Each native scan processes at most 4 MiB in 64 KiB buffers with linear KMP matching, including matches crossing buffer/scan boundaries. The UI yields between scans, reports progress and can cancel before the next scan. Clear/eviction cancels scans at a buffer boundary. Search freezes the recorded byte count at click time: a result on a partial/live capture describes only that range, and later bytes require a new search. No-match does not automatically wrap.

**JSON layout** prepares a separate temporary formatted view for a completed body. The engine validates JSON without constructing its value tree, then changes only whitespace outside strings. Duplicate keys, original number spelling/precision, key order and escapes are preserved. UTF-8 and nesting are checked; nesting deeper than 128 levels is rejected for layout while the raw body stays available. Invalid/incomplete JSON is never silently repaired. Preparation is cancellable, and retries are explicit. Both the source and formatted file count toward the same session disk budget, so a large expansion can fail without affecting the original. At most two analysis jobs (search scans or JSON preparation) run at once. A body has only one preparation job.

The formatted file is still read in pages of at most 64 KiB; large strings do not require loading the entire value into memory or the webview. Offsets in JSON layout refer to that formatted file. Search always switches back to original decoded-byte offsets. The formatted view is presentation only, not a modified response or a redacted export. Clear, eviction and normal exit remove it with its capture. Crashes can leave `sippin-json-*` files as well as body files; both contain unredacted data.

**Review export** is available after a body capture completes. The preview exposes the direction, byte count and redaction status before opening the native save dialog; the engine validates them again when export begins. Request export copies the redacted inspection representation, never the original request bytes. Response export copies the original decoded inspection body and therefore requires a checkbox acknowledging that it may contain secrets or personal data. The Rust host copies directly between files without loading the body into the webview. The selected destination may be overwritten, becomes user-owned, and is not managed by Clear, eviction or retention. JSON layout is not exported; export always uses the original recorded inspection representation.

Identity, gzip (including multiple members), zlib-wrapped deflate and Brotli are decoded progressively for inspection; forwarding preserves the original encoded bytes. Unsupported encoding stacks/codecs are reported as unavailable. The budget counts decoded bytes across retained recordings, so compressed expansion cannot bypass it. Disk exhaustion, quota exhaustion, corrupt compression, cancellation and interrupted transport are visible as partial/unavailable capture states. Such capture errors do not intentionally truncate the response sent to the client; Stop still cancels transport. No response is presented as fully captured after a known capture failure.

Response body contents are **not redacted or encrypted at rest**. JSON request inspection files contain the built-in and custom-path redacted representation, but are also unencrypted. Recording is off by default and is never enabled by merely launching the app. Clear, retention eviction and normal exit remove temporary files; a crash may leave files behind, and deletion is not secure erasure. This is temporary inspection storage, not session persistence or portable export. HTTPS bodies remain inaccessible inside opaque CONNECT tunnels.

## Validation

Run `cargo test -p sippin-soda-engine` for real local TCP/HTTP/TLS fixtures. They cover forwarding, header rewriting/redaction, unsupported targets, loops, upstream errors, timeouts, stopping, port reuse, retention and large responses. CONNECT tests additionally verify early bytes, half-close, live counts, tracked concurrency, bounded lifetime and HTTPS with trusted/untrusted test certificates. Test certificates are ephemeral and trusted only by the test client; they never enter the OS trust store. See ADR 0001 for the remaining TLS interception and performance decision gates.

## HTTPS pass-through

With the proxy running, send a request to an HTTPS service you intend to test:

```sh
curl --noproxy "" --proxy http://127.0.0.1:8080 https://example.com/
```

Keep the proxy URL as `http://`: CONNECT creates the tunnel and the client then negotiates TLS directly with the destination. Use your development server's CA with curl's `--cacert` when needed; the proxy neither trusts certificates on your behalf nor disables client verification.

The UI shows `CONNECT example.com:443` and `200 · Tunnel`. This 200 means the TCP tunnel opened, **not** that the HTTPS API returned 200. Paths, query strings, inner headers, bodies and inner statuses are not visible. Recorded headers belong only to the CONNECT negotiation and use the usual redaction rules. Byte counts measure forwarded opaque transport bytes in each direction, including TLS handshakes; payload bytes are never retained. TLS alerts and certificate failures are opaque too, so the capture cannot diagnose the client's TLS validation result. Stop closes both ends of active tunnels. No certificate authority or TLS interception is enabled.

## Local CA foundation

Settings can generate a five-year local development CA only after explicit consent. Its private key and certificate are stored in the operating-system credential store under Sippin Soda's application identity; the private key never crosses IPC. The UI shows creation/expiry timestamps and the SHA-256 fingerprint, and a native save dialog can export only the public PEM certificate. Generation does not install or trust the certificate, change proxy settings, or enable HTTPS inspection. The application reports `httpsInspection: false` even while CA material exists.

Removing the local CA requires a separate confirmation and deletes only the credential owned by Sippin Soda. It cannot recall public certificate files or trust-store entries created manually outside the app. Regeneration requires removal first so identity changes are deliberate.

The engine can issue a short-lived certificate scoped to one validated DNS name or IP address. Issuance is authorized only for destinations classified as Development; Production and Unknown fail closed before credential-store access. The certificate lasts at most 24 hours and never beyond the CA expiry. Its newly generated private key remains zeroized engine memory and is not exposed through IPC. A local TLS fixture verifies that a client trusting the CA accepts the exact requested host and rejects a different host. CONNECT still uses opaque pass-through: upstream TLS verification, interception, trust-store install/verification/removal and rotation workflows remain subsequent slices.
