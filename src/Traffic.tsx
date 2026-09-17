import { useState } from "react";
import type { Capture, Snapshot } from "./engine";
import { ResponseBody } from "./ResponseBody";

function Headers({ values }: { values: Capture["requestHeaders"] }) {
  return values.length ? (
    <dl className="header-list">
      {values.map(([name, value], index) => (
        <div key={`${name}-${index}`}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  ) : (
    <p>No headers recorded.</p>
  );
}

export function Traffic({
  snapshot,
  desktop,
  busy,
  proxyCredential,
  clear,
  replay,
  resolveBreakpoint,
}: {
  snapshot: Snapshot | null;
  desktop: boolean;
  busy: boolean;
  proxyCredential: { profileId: string; token: string } | null;
  clear: () => void;
  replay: (id: number) => void;
  resolveBreakpoint: (
    id: number,
    status: number | null,
    body?: string | null,
    contentType?: string | null,
  ) => void;
}) {
  const [query, setQuery] = useState("");
  const [selectedId, select] = useState<number | null>(null);
  const [tab, setTab] = useState("Request");
  const [replacementStatus, setReplacementStatus] = useState("200");
  const [replacementContentType, setReplacementContentType] =
    useState("application/json");
  const [replacementBody, setReplacementBody] = useState('{\n  "ok": true\n}');
  const traffic = snapshot?.traffic ?? [];
  const selected = traffic.find((capture) => capture.id === selectedId);
  const canReplay =
    selected?.destinationClass === "development" &&
    selected.kind === "http" &&
    (selected.method === "GET" || selected.method === "HEAD") &&
    selected.requestBytes === 0 &&
    selected.phase === "complete";
  const filtered = traffic.filter((capture) =>
    `${capture.method} ${capture.target} ${capture.status ?? ""}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const running = snapshot?.status.phase === "running";
  const proxyAuth = proxyCredential
    ? ` --proxy-user "${proxyCredential.profileId}:${proxyCredential.token}"`
    : "";

  return (
    <>
      <div className="proxy-help">
        <strong>
          {running
            ? `Listening on ${snapshot.status.listenAddress}`
            : "HTTP proxy + CONNECT tunnels"}
        </strong>
        <p>
          {desktop
            ? "Configure your client to use this proxy. System proxy settings are never changed automatically."
            : "This browser preview cannot start the proxy. Open the desktop app to capture real traffic."}
        </p>
        <p>
          HTTP metadata + optional body inspection · JSON requests are redacted
          before storage ·{" "}
          {snapshot?.status.httpsInspection
            ? "Development TLS termination with HTTP/1.1 and HTTP/2 capture is enabled."
            : "HTTPS content stays in opaque tunnels; the CA is never installed automatically."}
        </p>
      </div>
      <div className="traffic-toolbar">
        <label className="search-label">
          Filter traffic
          <input
            type="search"
            placeholder="Method, host, path or status…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <span>{traffic.length} / 200 retained</span>
        <button onClick={clear} disabled={!desktop || busy || !traffic.length}>
          Clear
        </button>
      </div>
      {(snapshot?.status.evictedCaptures ?? 0) > 0 && (
        <p className="capture-notice">
          {snapshot?.status.evictedCaptures} older captures were evicted from
          memory.
        </p>
      )}
      {(snapshot?.status.rejectedConnections ?? 0) > 0 && (
        <p className="capture-notice">
          {snapshot?.status.rejectedConnections} connections rejected at the
          concurrency limit.
        </p>
      )}
      <div className="traffic-table live-traffic">
        <table>
          <thead>
            <tr>
              {["METHOD / TARGET", "SAFETY", "STATUS", "TIME", "RECEIVED"].map(
                (label) => (
                  <th key={label}>{label}</th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {filtered.map((capture) => (
              <tr
                key={capture.id}
                className={`${selectedId === capture.id ? "active-row" : ""} safety-${capture.destinationClass}`}
              >
                <td>
                  <button
                    className="request-select"
                    onClick={() => select(capture.id)}
                    aria-pressed={selectedId === capture.id}
                  >
                    <b>{capture.method}</b>
                    <span>{capture.target}</span>
                  </button>
                </td>
                <td>
                  <span className={`safety-badge ${capture.destinationClass}`}>
                    {capture.destinationClass}
                  </span>
                </td>
                <td>
                  {capture.phase === "error"
                    ? `${capture.status ?? "—"} · Error`
                    : capture.kind === "tls" && capture.status === 200
                      ? "200 · TLS bridge"
                      : capture.kind === "tunnel" && capture.status === 200
                        ? "200 · Tunnel"
                        : capture.responseRuleId
                          ? `${capture.status ?? "—"} · Rule`
                          : (capture.status ?? "Pending")}
                </td>
                <td>
                  {capture.phase === "pending"
                    ? "In progress"
                    : `${capture.durationMs} ms`}
                </td>
                <td>{capture.responseBytes.toLocaleString()} B</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && (
          <div className="empty-state">
            <span className="eyebrow">
              {query ? "NO MATCHES" : "READY WHEN YOU ARE"}
            </span>
            <h2>
              {query
                ? "No requests match this filter."
                : running
                  ? "Waiting for your first request."
                  : "Let’s see what’s flowing."}
            </h2>
            <p>
              {query
                ? "Try a different host, method or status."
                : running
                  ? "Send an HTTP or HTTPS request through the proxy configured above."
                  : "Start the proxy in the desktop app, then configure your HTTP client."}
            </p>
            {!query && (
              <code className="setup-command">{`curl --noproxy ""${proxyAuth} --proxy http://${snapshot?.status.listenAddress ?? "127.0.0.1:8080"} http://127.0.0.1:9090/health`}</code>
            )}
            <p>Use the local fixture from the development guide.</p>
          </div>
        )}
      </div>
      <section
        className="inspector live-inspector"
        aria-label="Request inspector"
      >
        <span className="inspector-title">REQUEST INSPECTOR</span>
        {selected ? (
          <>
            <h2>
              {selected.method} {selected.target}
            </h2>
            <p className={`destination-class ${selected.destinationClass}`}>
              Effective destination: {selected.destinationClass}. Production
              Safety Mode applies to active operations using this
              classification.
            </p>
            {selected.clientProfileId && (
              <p>Authenticated client profile: {selected.clientProfileId}</p>
            )}
            {selected.replayOf && (
              <p>Replay of capture #{selected.replayOf}.</p>
            )}
            {selected.responseRuleName && (
              <p className="capture-notice">
                Response rule applied: {selected.responseRuleName}.
              </p>
            )}
            <div className="capture-actions">
              <button
                onClick={() => replay(selected.id)}
                disabled={!desktop || busy || !canReplay}
                title={
                  canReplay
                    ? "Replay this request to the same Development URL"
                    : "Replay currently supports completed, bodyless HTTP GET/HEAD captures in Development"
                }
              >
                Replay
              </button>
              <span>
                Same Development URL; Authorization, cookies and API keys are
                excluded.
              </span>
            </div>
            {selected.kind === "tunnel" && (
              <p className="capture-notice">
                Opaque CONNECT tunnel. Status 200 means the tunnel opened; the
                inner API status, headers and body are not inspected. Byte
                counts include transport data such as TLS handshakes.
              </p>
            )}
            {selected.kind === "tls" && (
              <p className="capture-notice">
                Development TLS inspection was selected, but no complete inner
                HTTP/1 request was captured. Check the transfer error below.
              </p>
            )}
            {selected.kind === "https" && (
              <p className="capture-notice">
                HTTPS was terminated only for this authorized Development
                destination and separately verified upstream. The inner HTTP/1
                exchange uses the same capture and redaction rules as HTTP,
                including multiplexed HTTP/2 streams.
              </p>
            )}
            <div className="detail-tabs" aria-label="Inspector view">
              {["Request", "Response", "Timing"].map((name) => (
                <button
                  key={name}
                  onClick={() => setTab(name)}
                  aria-pressed={tab === name}
                >
                  {name}
                </button>
              ))}
            </div>
            {selected.error && (
              <p role="status" className="error">
                {selected.error}
              </p>
            )}
            {selected.breakpointState === "waiting" && (
              <div className="capture-notice" role="status">
                <p>
                  Development response paused with status{" "}
                  {selected.originalStatus}. It continues unchanged
                  automatically after 15 seconds.
                </p>
                <button
                  onClick={() => resolveBreakpoint(selected.id, null)}
                  disabled={busy}
                >
                  Continue unchanged
                </button>{" "}
                <button
                  onClick={() => resolveBreakpoint(selected.id, 500)}
                  disabled={busy}
                >
                  Return 500
                </button>{" "}
                <button
                  onClick={() => resolveBreakpoint(selected.id, 503)}
                  disabled={busy}
                >
                  Return 503
                </button>
                <div className="breakpoint-replacement">
                  <label>
                    Status
                    <input
                      type="number"
                      min="200"
                      max="599"
                      value={replacementStatus}
                      onChange={(event) =>
                        setReplacementStatus(event.target.value)
                      }
                    />
                  </label>
                  <label>
                    Content-Type
                    <input
                      value={replacementContentType}
                      maxLength={128}
                      onChange={(event) =>
                        setReplacementContentType(event.target.value)
                      }
                    />
                  </label>
                  <label>
                    Replacement body (max 64 KiB UTF-8)
                    <textarea
                      rows={6}
                      value={replacementBody}
                      onChange={(event) =>
                        setReplacementBody(event.target.value)
                      }
                    />
                  </label>
                  <button
                    onClick={() =>
                      resolveBreakpoint(
                        selected.id,
                        Number(replacementStatus),
                        replacementBody,
                        replacementContentType,
                      )
                    }
                    disabled={
                      busy ||
                      Number(replacementStatus) < 200 ||
                      Number(replacementStatus) > 599 ||
                      new TextEncoder().encode(replacementBody).length >
                        65536 ||
                      !replacementContentType.trim()
                    }
                  >
                    Return replacement
                  </button>
                </div>
              </div>
            )}
            {tab === "Request" ? (
              <>
                <p>
                  {selected.requestBytes.toLocaleString()} bytes forwarded.
                  Query values and non-allowlisted header values are redacted.
                </p>
                {(selected.kind === "tunnel" || selected.kind === "tls") && (
                  <p>CONNECT negotiation headers only.</p>
                )}
                <Headers values={selected.requestHeaders} />
                {selected.requestBodyState === "disabled" ? (
                  selected.requestBytes > 0 && (
                    <p>
                      Request body recording was disabled when the proxy
                      started.
                    </p>
                  )
                ) : selected.requestBodyState === "empty" ? (
                  <p>No request body.</p>
                ) : (
                  <ResponseBody
                    key={`request-${selected.id}`}
                    id={selected.id}
                    desktop={desktop}
                    pending={selected.requestBodyState === "recording"}
                    recordingError={selected.requestBodyError}
                    direction="request"
                  />
                )}
              </>
            ) : tab === "Response" ? (
              <>
                <p>
                  {selected.kind === "tunnel" ? "CONNECT result" : "Status"}:{" "}
                  {selected.status ?? "Waiting"} ·{" "}
                  {selected.responseBytes.toLocaleString()} bytes received
                </p>
                {(selected.breakpointState === "modified" ||
                  selected.responseRuleId) && (
                  <p>Original upstream status: {selected.originalStatus}.</p>
                )}
                {selected.kind === "tunnel" || selected.kind === "tls" ? (
                  <p>Inner response headers are not available.</p>
                ) : (
                  <>
                    <Headers values={selected.responseHeaders} />
                    <ResponseBody
                      key={selected.id}
                      id={selected.id}
                      desktop={desktop}
                      pending={selected.phase === "pending"}
                      recordingError={selected.responseBodyError}
                    />
                  </>
                )}
              </>
            ) : (
              <dl>
                <dt>Started</dt>
                <dd>{new Date(selected.startedAt).toLocaleString()}</dd>
                <dt>Transfer state</dt>
                <dd>{selected.phase}</dd>
                <dt>Elapsed</dt>
                <dd>
                  {selected.phase === "pending"
                    ? "In progress"
                    : `${selected.durationMs} ms`}
                </dd>
              </dl>
            )}
            <p>
              {selected.kind === "https"
                ? "Only authorized inner HTTP exchanges are inspected; TLS records are not retained. "
                : "Encrypted tunnel contents are not recorded. "}
              HTTP body recording must be enabled before Start; request
              inspection currently accepts JSON up to 1 MiB and stores only its
              redacted copy.
            </p>
          </>
        ) : (
          <p>
            {selectedId === null
              ? "Select a captured request to explore its details."
              : "The selected capture was cleared or evicted. Select another request."}
          </p>
        )}
      </section>
    </>
  );
}
