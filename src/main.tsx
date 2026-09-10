import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { useEngine } from "./engine";
import { Traffic } from "./Traffic";
import "./styles.css";

const sections = [
  "Traffic",
  "Collections",
  "Mocks",
  "Rules",
  "Scenarios",
  "Environments",
  "Sessions",
  "Settings",
] as const;
type Section = (typeof sections)[number];
const descriptions: Record<Section, string> = {
  Traffic: "Your application’s traffic, in one place.",
  Collections: "Compose requests and keep repeatable workflows together.",
  Mocks: "Give your application a response you control.",
  Rules: "Turn a debugging decision into repeatable behavior.",
  Scenarios: "Bring rules, routes and mocks together.",
  Environments: "Connect the services you need, wherever they run.",
  Sessions: "Keep the context behind a debugging session.",
  Settings: "Make Sippin Soda feel at home.",
};

function Glass({ large = false }: { large?: boolean }) {
  return (
    <svg
      className={large ? "glass large" : "glass"}
      viewBox="0 0 48 56"
      fill="none"
      aria-hidden="true"
    >
      <path
        className="straw"
        d="M25 32 31 8l9-5"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
      />
      <path
        d="m8 19 4 30c.2 2 2 3 4 3h16c2 0 3.8-1 4-3l4-30H8Z"
        fill="currentColor"
        fillOpacity=".09"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinejoin="round"
      />
      <path d="M12 34c9-5 15 5 24 0" stroke="currentColor" strokeWidth="2" />
      <circle cx="21" cy="42" r="1.5" fill="currentColor" />
      <circle cx="29" cy="46" r="1.5" fill="currentColor" />
    </svg>
  );
}

function App() {
  const [section, setSection] = useState<Section>("Traffic");
  const [theme, setTheme] = useState(
    () => localStorage.getItem("sippin-theme") || "system",
  );
  const { snapshot, error, busy, command, desktop } = useEngine();
  const status = snapshot?.status;
  const running = status?.phase === "running";
  const [port, setPort] = useState("8080");
  const [captureBodies, setCaptureBodies] = useState(false);
  const [diskBudget, setDiskBudget] = useState("10");
  const [redactionPaths, setRedactionPaths] = useState("");
  const [developmentHosts, setDevelopmentHosts] = useState("");
  const [productionHosts, setProductionHosts] = useState("");
  const parseHostRules = (value: string) =>
    value
      .split(/[\n,]/)
      .map((host) => host.trim())
      .filter(Boolean);
  const parsedDevelopmentHosts = parseHostRules(developmentHosts);
  const parsedProductionHosts = parseHostRules(productionHosts);
  const hostRuleIsPlausible = (host: string) =>
    host.length <= 253 &&
    /^[\x21-\x7e]+$/.test(host) &&
    (!host.includes("*") || (host.startsWith("*.") && !host.slice(2).includes("*")));
  const validHostRules =
    parsedDevelopmentHosts.length <= 128 &&
    parsedProductionHosts.length <= 128 &&
    [...parsedDevelopmentHosts, ...parsedProductionHosts].every(
      hostRuleIsPlausible,
    );
  const parsedRedactionPaths = redactionPaths
    .split(/[\n,]/)
    .map((path) => path.trim())
    .filter(Boolean);
  const validRedactionPaths =
    parsedRedactionPaths.length <= 64 &&
    parsedRedactionPaths.every(
      (path) => path.startsWith("/") && path.length <= 512,
    );
  const validBudget =
    /^\d+$/.test(diskBudget) &&
    Number(diskBudget) >= 1 &&
    Number(diskBudget) <= 1024;
  const validPort =
    /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("sippin-theme", theme);
  }, [theme]);

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Application navigation">
        <div className="brand">
          <Glass />
          <span>
            Sippin Soda<small>DEVELOPMENT WORKSPACE</small>
          </span>
        </div>
        <div className="project">
          <span className="project-icon">S</span>
          <div>
            Local workspace<small>On this device</small>
          </div>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {sections.map((item, index) => (
            <button
              key={item}
              className={section === item ? "nav-item selected" : "nav-item"}
              aria-current={section === item ? "page" : undefined}
              onClick={() => setSection(item)}
            >
              <span className="nav-icon" aria-hidden="true">
                {["↔", "▤", "◇", "≡", "◈", "◎", "▷", "⚙"][index]}
              </span>
              {item}
              {item === "Traffic" && (
                <span className="count">{status?.captures ?? 0}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="local-dot" /> Local-first. Yours by default.
          <small>v0.1 · Proxy preview</small>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <span>
            Workspace <span className="slash">/</span>{" "}
            <strong>{section}</strong>
          </span>
          <div className="connection">
            <span className="status-dot" />
            {desktop
              ? status
                ? running
                  ? "HTTP + CONNECT active"
                  : "Proxy stopped"
                : "Connecting to engine…"
              : "UI preview"}
            <span className="environment">LOCAL</span>
          </div>
        </header>
        <div className="page-heading">
          <div>
            <div className="eyebrow">OBSERVE. UNDERSTAND. TAKE CONTROL.</div>
            <h1>{section}</h1>
            <p>{descriptions[section]}</p>
          </div>
          {section === "Traffic" && (
            <div className="proxy-controls">
              <label>
                Port
                <input
                  aria-label="Proxy port"
                  inputMode="numeric"
                  value={port}
                  onChange={(event) => setPort(event.target.value)}
                  disabled={running || busy}
                />
              </label>
              <button
                className="primary"
                disabled={
                  !desktop ||
                  !status ||
                  busy ||
                  (!running &&
                    (!validPort ||
                      !validBudget ||
                      !validRedactionPaths ||
                      !validHostRules))
                }
                onClick={() =>
                  void command(
                    running ? "stop_proxy" : "start_proxy",
                    running
                      ? undefined
                      : {
                          port: Number(port),
                          captureBodies,
                          diskBudgetGib: Number(diskBudget),
                          requestRedactionPaths: parsedRedactionPaths,
                          developmentHosts: parsedDevelopmentHosts,
                          productionHosts: parsedProductionHosts,
                        },
                  )
                }
              >
                {busy ? "Please wait…" : running ? "Stop proxy" : "Start proxy"}
              </button>
            </div>
          )}
        </div>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {section === "Traffic" ? (
          <>
            <div className="body-options">
              <label>
                <input
                  type="checkbox"
                  checked={captureBodies}
                  disabled={running || busy || !desktop}
                  onChange={(event) => setCaptureBodies(event.target.checked)}
                />{" "}
                Record HTTP bodies
              </label>
              <label>
                Session disk budget (GiB){" "}
                <input
                  type="number"
                  min="1"
                  max="1024"
                  value={diskBudget}
                  disabled={running || busy || !desktop}
                  onChange={(event) => setDiskBudget(event.target.value)}
                />
              </label>
              <label className="redaction-paths">
                Additional JSON Pointer redactions
                <textarea
                  rows={3}
                  value={redactionPaths}
                  disabled={running || busy || !desktop}
                  aria-invalid={!validRedactionPaths}
                  placeholder={"/customer/email\n/items/*/cardNumber"}
                  onChange={(event) => setRedactionPaths(event.target.value)}
                />
              </label>
              {!validRedactionPaths && (
                <p className="error" role="alert">
                  Use at most 64 JSON Pointers, each beginning with / and no
                  longer than 512 characters.
                </p>
              )}
              <div className="destination-rules">
                <label className="redaction-paths">
                  Development hosts
                  <textarea
                    rows={3}
                    value={developmentHosts}
                    disabled={running || busy || !desktop}
                    aria-invalid={!validHostRules}
                    placeholder={"api.dev.example\n*.internal"}
                    onChange={(event) => setDevelopmentHosts(event.target.value)}
                  />
                </label>
                <label className="redaction-paths">
                  Production hosts
                  <textarea
                    rows={3}
                    value={productionHosts}
                    disabled={running || busy || !desktop}
                    aria-invalid={!validHostRules}
                    placeholder={"api.example.com\n*.prod.example"}
                    onChange={(event) => setProductionHosts(event.target.value)}
                  />
                </label>
              </div>
              {!validHostRules && (
                <p className="error" role="alert">
                  Use at most 128 ASCII host rules per class. Wildcards must be
                  the leading form *.example.com.
                </p>
              )}
              <p>
                Destination safety uses the effective target host. Loopback is
                Development automatically; configured rules may use an exact
                host or a leading wildcard. Unlisted destinations remain
                Unknown, and Development/Production overlaps are rejected.
              </p>
              <p>
                Responses have no per-body size cap and remain unredacted.
                JSON requests up to 1 MiB are redacted before temporary-disk
                storage; built-in secret keys are always protected and these
                additional paths support * for array/object members. Other
                request formats are not recorded. Body files are read in 64 KiB
                pages and are not encrypted at rest. Clear, eviction and normal
                app exit remove them; Stop keeps them available.
              </p>
            </div>
            <Traffic
              snapshot={snapshot}
              desktop={desktop}
              busy={busy}
              clear={() => void command("clear_traffic")}
            />
          </>
        ) : section === "Settings" ? (
          <div className="settings-panel">
            <h2>Appearance</h2>
            <p>Choose a theme for this workspace.</p>
            <label htmlFor="theme">Color theme</label>
            <select
              id="theme"
              value={theme}
              onChange={(event) => setTheme(event.target.value)}
            >
              <option value="system">System</option>
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
            <div className="settings-divider" />
            <h2>Engine</h2>
            <p>
              {desktop
                ? "The local Rust engine handles HTTP capture and opaque CONNECT tunnels."
                : "Browser preview. Run npm run desktop to use the native application."}
            </p>
            <dl>
              <dt>Proxy</dt>
              <dd>{running ? "Running" : "Stopped"}</dd>
              <dt>Listen address</dt>
              <dd>{status?.listenAddress ?? "127.0.0.1:8080"}</dd>
              <dt>HTTPS inspection</dt>
              <dd>Not available · no CA installed</dd>
              <dt>HTTPS pass-through</dt>
              <dd>CONNECT supported · 5 minute tunnel limit</dd>
              <dt>Production policy</dt>
              <dd>
                {status?.productionProtection
                  ? "Observation only; replay and modification unavailable"
                  : "Read-only by design"}
              </dd>
            </dl>
          </div>
        ) : (
          <div className="planned-panel">
            <span className="eyebrow">ON THE ROADMAP</span>
            <h2>{section}, with purpose.</h2>
            <p>{descriptions[section]}</p>
            <p className="muted">
              This module is specified and has not been implemented yet.
              <br />
              We’re building the live traffic workflow first.
            </p>
            <button onClick={() => setSection("Traffic")}>
              Back to Traffic <span aria-hidden="true">→</span>
            </button>
          </div>
        )}
        <footer className="statusbar">
          <span>
            <span className="local-dot" /> All data stays on this device
          </span>
          <span>
            {desktop ? "Desktop" : "Development preview"}
            <span className="slash">·</span>{" "}
            {running ? "HTTP + CONNECT active" : "Proxy stopped"}
          </span>
        </footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
