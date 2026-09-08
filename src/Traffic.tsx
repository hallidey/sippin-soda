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
  clear,
}: {
  snapshot: Snapshot | null;
  desktop: boolean;
  busy: boolean;
  clear: () => void;
}) {
  const [query, setQuery] = useState("");
  const [selectedId, select] = useState<number | null>(null);
  const [tab, setTab] = useState("Request");
  const traffic = snapshot?.traffic ?? [];
  const selected = traffic.find((capture) => capture.id === selectedId);
  const filtered = traffic.filter((capture) =>
    `${capture.method} ${capture.target} ${capture.status ?? ""}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const running = snapshot?.status.phase === "running";

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
          HTTP metadata + optional response body files · HTTPS content stays
          encrypted; no CA is installed.
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
              {["METHOD / TARGET", "STATUS", "TIME", "RECEIVED"].map(
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
                className={selectedId === capture.id ? "active-row" : ""}
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
                  {capture.phase === "error"
                    ? `${capture.status ?? "—"} · Error`
                    : capture.kind === "tunnel" && capture.status === 200
                      ? "200 · Tunnel"
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
              <code className="setup-command">{`curl --noproxy "" --proxy http://${snapshot?.status.listenAddress ?? "127.0.0.1:8080"} http://127.0.0.1:9090/health`}</code>
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
            {selected.kind === "tunnel" && (
              <p className="capture-notice">
                Opaque CONNECT tunnel. Status 200 means the tunnel opened; the
                inner API status, headers and body are not inspected. Byte
                counts include transport data such as TLS handshakes.
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
            {tab === "Request" ? (
              <>
                <p>
                  {selected.requestBytes.toLocaleString()} bytes forwarded.
                  Query values and non-allowlisted header values are redacted.
                </p>
                {selected.kind === "tunnel" && (
                  <p>CONNECT negotiation headers only.</p>
                )}
                <Headers values={selected.requestHeaders} />
              </>
            ) : tab === "Response" ? (
              <>
                <p>
                  {selected.kind === "tunnel" ? "CONNECT result" : "Status"}:{" "}
                  {selected.status ?? "Waiting"} ·{" "}
                  {selected.responseBytes.toLocaleString()} bytes received
                </p>
                {selected.kind === "tunnel" ? (
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
              Request bodies and encrypted tunnel contents are not recorded.
              HTTP response recording must be enabled before Start.
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
