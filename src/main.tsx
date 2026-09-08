import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke, isTauri } from "@tauri-apps/api/core";
import "./styles.css";

type EngineStatus = {
  phase: "not_implemented";
  listenAddress: string;
  captures: number;
  httpsInspection: boolean;
  productionProtection: boolean;
};
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
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [error, setError] = useState("");
  const desktop = isTauri();

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("sippin-theme", theme);
  }, [theme]);
  useEffect(() => {
    if (desktop)
      invoke<EngineStatus>("engine_status")
        .then(setStatus)
        .catch(() =>
          setError(
            "Unable to read engine status. Restart the desktop application.",
          ),
        );
  }, [desktop]);

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
              {item === "Traffic" && <span className="count">0</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="local-dot" /> Local-first. Yours by default.
          <small>v0.1 · Foundation</small>
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
                ? "Proxy not started"
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
            <button
              className="primary"
              disabled
              title="Capture will be available after the HTTP proxy milestone"
            >
              Start capture <span aria-hidden="true">↗</span>
            </button>
          )}
        </div>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {section === "Traffic" ? (
          <>
            <div className="traffic-toolbar">
              <span>
                All traffic <span className="pill">0</span>
              </span>
              <span className="muted">
                Capture will be available in the next milestone
              </span>
            </div>
            <div
              className="traffic-table"
              role="table"
              aria-label="Captured traffic"
            >
              <div className="table-head" role="row">
                {["METHOD", "HOST / PATH", "STATUS", "DURATION", "SIZE"].map(
                  (label) => (
                    <span role="columnheader" key={label}>
                      {label}
                    </span>
                  ),
                )}
              </div>
              <div className="empty-state">
                <div className="logo-tile">
                  <Glass large />
                </div>
                <span className="eyebrow">A CLEAR VIEW STARTS HERE</span>
                <h2>Let’s see what’s flowing.</h2>
                <p>
                  This workspace is ready for its first request.
                  <br />
                  The HTTP proxy is the next development milestone.
                </p>
                <div className="empty-note">
                  <span className="status-dot" /> No proxy is listening. No
                  traffic is being captured.
                </div>
              </div>
            </div>
            <div className="inspector">
              <span className="inspector-title">REQUEST INSPECTOR</span>
              <p>Select a captured request to explore its details.</p>
              <div
                className="inspector-tabs"
                aria-label="Planned inspector views"
              >
                Request <span>Response</span> <span>Headers</span>{" "}
                <span>Timing</span>
              </div>
            </div>
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
                ? "Desktop bridge connected to the local Rust engine contract."
                : "Browser preview. Run npm run desktop to use the native application."}
            </p>
            <dl>
              <dt>Proxy</dt>
              <dd>Not implemented yet</dd>
              <dt>Planned listen address</dt>
              <dd>{status?.listenAddress ?? "127.0.0.1:8080"}</dd>
              <dt>HTTPS inspection</dt>
              <dd>Not available · no CA installed</dd>
              <dt>Production policy</dt>
              <dd>
                {status?.productionProtection
                  ? "Read-only policy defined in engine"
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
            <span className="slash">·</span> HTTP proxy planned
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
