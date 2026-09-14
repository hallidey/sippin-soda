import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
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
type CaStatus = {
  state: "absent" | "ready";
  fingerprintSha256: string | null;
  createdAt: number | null;
  expiresAt: number | null;
  installedByApp: boolean;
  httpsInspection: boolean;
};
type TlsTrustCheckStatus = {
  state: "idle" | "waiting" | "verified" | "failed" | "expired";
  client: TlsClientProfile | null;
  url: string | null;
  expiresAt: number | null;
  verifiedAt: number | null;
  error: string | null;
};
type TlsClientProfile = {
  id: string;
  name: string;
};
type ProxyCredential = {
  profileId: string;
  token: string;
};
type TlsInspectionPreflight = {
  state:
    | "proxy_stopped"
    | "client_authentication_required"
    | "disabled"
    | "missing_ca"
    | "expired_ca"
    | "client_trust_unverified"
    | "client_mismatch"
    | "ready";
  canEnableDevelopment: boolean;
  httpsInspectionActive: boolean;
  clientProfileId: string | null;
  verifiedClient: TlsClientProfile | null;
  proofExpiresAt: number | null;
};

const clientProfilesKey = "sippin-tls-client-profiles";

function loadClientProfiles(): TlsClientProfile[] {
  try {
    const value: unknown = JSON.parse(
      localStorage.getItem(clientProfilesKey) ?? "[]",
    );
    if (!Array.isArray(value)) return [];
    return value.filter(
      (profile): profile is TlsClientProfile =>
        typeof profile === "object" &&
        profile !== null &&
        typeof (profile as TlsClientProfile).id === "string" &&
        typeof (profile as TlsClientProfile).name === "string",
    );
  } catch {
    return [];
  }
}
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
  const [breakOnResponses, setBreakOnResponses] = useState(false);
  const [diskBudget, setDiskBudget] = useState("10");
  const [redactionPaths, setRedactionPaths] = useState("");
  const [developmentHosts, setDevelopmentHosts] = useState("");
  const [productionHosts, setProductionHosts] = useState("");
  const [caStatus, setCaStatus] = useState<CaStatus | null>(null);
  const [caConsent, setCaConsent] = useState(false);
  const [caRemoveConfirmed, setCaRemoveConfirmed] = useState(false);
  const [caBusy, setCaBusy] = useState(false);
  const [caMessage, setCaMessage] = useState("");
  const [trustCheck, setTrustCheck] = useState<TlsTrustCheckStatus | null>(
    null,
  );
  const [trustCheckConsent, setTrustCheckConsent] = useState(false);
  const [trustCheckBusy, setTrustCheckBusy] = useState(false);
  const [clientProfiles, setClientProfiles] = useState(loadClientProfiles);
  const [selectedClientId, setSelectedClientId] = useState(
    () => loadClientProfiles()[0]?.id ?? "",
  );
  const [newClientName, setNewClientName] = useState("");
  const [requireClientAuth, setRequireClientAuth] = useState(false);
  const [enableHttpsInspection, setEnableHttpsInspection] = useState(false);
  const [proxyCredential, setProxyCredential] =
    useState<ProxyCredential | null>(null);
  const [tlsPreflight, setTlsPreflight] =
    useState<TlsInspectionPreflight | null>(null);
  const selectedClient =
    clientProfiles.find((profile) => profile.id === selectedClientId) ?? null;
  const activeProxyClient =
    clientProfiles.find((profile) => profile.id === status?.clientProfileId) ??
    null;
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
    (!host.includes("*") ||
      (host.startsWith("*.") && !host.slice(2).includes("*")));
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
  const canRequestHttpsInspection =
    requireClientAuth &&
    selectedClient !== null &&
    caStatus?.state === "ready" &&
    (caStatus.expiresAt ?? 0) > Date.now() &&
    trustCheck?.state === "verified" &&
    trustCheck.client?.id === selectedClient.id &&
    (trustCheck.expiresAt ?? 0) > Date.now();
  const preflightMessage: Record<TlsInspectionPreflight["state"], string> = {
    proxy_stopped: "Start the proxy before evaluating HTTPS inspection.",
    client_authentication_required:
      "Start the proxy with client profile authentication.",
    disabled: "HTTPS inspection has not been explicitly enabled.",
    missing_ca: "Generate the local development CA first.",
    expired_ca: "The local development CA has expired.",
    client_trust_unverified:
      "Run the trust check with the authenticated client profile.",
    client_mismatch:
      "The authenticated proxy profile does not match the verified client.",
    ready:
      "Proxy identity and TLS trust proof match. Listener integration is not active yet.",
  };

  const createClientToken = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
      "",
    );
  };

  const proxyCommand = async () => {
    if (running) {
      if (await command("stop_proxy")) setProxyCredential(null);
      return;
    }
    const credential =
      requireClientAuth && selectedClient
        ? { profileId: selectedClient.id, token: createClientToken() }
        : null;
    const started = await command("start_proxy", {
      options: {
        port: Number(port),
        captureBodies,
        diskBudgetGib: Number(diskBudget),
        requestRedactionPaths: parsedRedactionPaths,
        developmentHosts: parsedDevelopmentHosts,
        productionHosts: parsedProductionHosts,
        clientProfileId: credential?.profileId ?? null,
        clientToken: credential?.token ?? null,
        enableHttpsInspection,
        breakOnResponses,
      },
    });
    setProxyCredential(started ? credential : null);
  };

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("sippin-theme", theme);
  }, [theme]);
  useEffect(() => {
    localStorage.setItem(clientProfilesKey, JSON.stringify(clientProfiles));
    if (
      selectedClientId &&
      !clientProfiles.some((profile) => profile.id === selectedClientId)
    ) {
      setSelectedClientId(clientProfiles[0]?.id ?? "");
    }
  }, [clientProfiles, selectedClientId]);
  useEffect(() => {
    if (!canRequestHttpsInspection) setEnableHttpsInspection(false);
  }, [canRequestHttpsInspection]);
  useEffect(() => {
    if (!desktop) return;
    let active = true;
    void Promise.all([
      invoke<CaStatus>("ca_status"),
      invoke<TlsTrustCheckStatus>("tls_trust_check_status"),
      invoke<TlsInspectionPreflight>("tls_inspection_preflight"),
    ])
      .then(([nextCa, nextTrust, nextPreflight]) => {
        if (active) {
          setCaStatus(nextCa);
          setTrustCheck(nextTrust);
          setTlsPreflight(nextPreflight);
        }
      })
      .catch((cause) => {
        if (active) setCaMessage(String(cause));
      });
    return () => {
      active = false;
    };
  }, [desktop]);
  useEffect(() => {
    if (!desktop) return;
    void invoke<TlsInspectionPreflight>("tls_inspection_preflight")
      .then(setTlsPreflight)
      .catch((cause) => setCaMessage(String(cause)));
  }, [desktop, snapshot?.revision, trustCheck?.state]);
  useEffect(() => {
    if (!desktop || !status?.httpsInspection) return;
    const timer = window.setInterval(() => {
      void invoke<TlsInspectionPreflight>("tls_inspection_preflight")
        .then(setTlsPreflight)
        .catch((cause) => setCaMessage(String(cause)));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [desktop, status?.httpsInspection]);
  useEffect(() => {
    if (!desktop || trustCheck?.state !== "waiting") return;
    const timer = window.setInterval(() => {
      void invoke<TlsTrustCheckStatus>("tls_trust_check_status")
        .then(setTrustCheck)
        .catch((cause) => setCaMessage(String(cause)));
    }, 500);
    return () => window.clearInterval(timer);
  }, [desktop, trustCheck?.state]);
  const caCommand = async (
    name: "generate_local_ca" | "remove_local_ca",
    args: Record<string, unknown>,
  ) => {
    setCaBusy(true);
    setCaMessage("");
    try {
      const next = await invoke<CaStatus>(name, args);
      setCaStatus(next);
      setCaConsent(false);
      setCaRemoveConfirmed(false);
      setTrustCheck(null);
      setTrustCheckConsent(false);
      setCaMessage(
        next.state === "ready"
          ? "Local CA generated in the operating-system credential store. It has not been installed or trusted."
          : "Local CA material removed from the credential store.",
      );
    } catch (cause) {
      setCaMessage(String(cause));
    } finally {
      setCaBusy(false);
    }
  };
  const trustCheckCommand = async (
    name: "start_tls_trust_check" | "cancel_tls_trust_check",
  ) => {
    setTrustCheckBusy(true);
    setCaMessage("");
    try {
      if (name === "start_tls_trust_check" && !selectedClient) {
        throw new Error("Choose a client profile before starting the check.");
      }
      const next = await invoke<TlsTrustCheckStatus>(
        name,
        name === "start_tls_trust_check"
          ? {
              clientId: selectedClient!.id,
              clientName: selectedClient!.name,
            }
          : undefined,
      );
      setTrustCheck(next);
      setTrustCheckConsent(false);
    } catch (cause) {
      setCaMessage(String(cause));
    } finally {
      setTrustCheckBusy(false);
    }
  };
  const addClientProfile = () => {
    const name = newClientName.trim();
    if (!name || name.length > 80) return;
    const profile = { id: crypto.randomUUID(), name };
    setClientProfiles((current) => [...current, profile]);
    setSelectedClientId(profile.id);
    setNewClientName("");
  };
  const removeSelectedClient = () => {
    if (!selectedClient || running) return;
    if (trustCheck?.client?.id === selectedClient.id) {
      void trustCheckCommand("cancel_tls_trust_check");
    }
    setClientProfiles((current) =>
      current.filter((profile) => profile.id !== selectedClient.id),
    );
  };
  const copyTrustCheckUrl = async () => {
    if (!trustCheck?.url) return;
    try {
      await navigator.clipboard.writeText(trustCheck.url);
      setCaMessage(
        "Temporary trust-check URL copied. Open it in the client you want to verify.",
      );
    } catch {
      setCaMessage(
        "Copy failed. Select the temporary URL and copy it manually.",
      );
    }
  };
  const exportCa = async () => {
    setCaBusy(true);
    setCaMessage("");
    try {
      const path = await invoke<string | null>("export_local_ca");
      setCaMessage(
        path
          ? `Public CA certificate exported to ${path}`
          : "Export cancelled.",
      );
    } catch (cause) {
      setCaMessage(String(cause));
    } finally {
      setCaBusy(false);
    }
  };

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
                      !validHostRules ||
                      (requireClientAuth && !selectedClient) ||
                      (enableHttpsInspection && !canRequestHttpsInspection)))
                }
                onClick={() => void proxyCommand()}
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
                <input
                  type="checkbox"
                  checked={breakOnResponses}
                  disabled={running || busy || !desktop}
                  onChange={(event) =>
                    setBreakOnResponses(event.target.checked)
                  }
                />{" "}
                Pause Development responses for 15 seconds
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={requireClientAuth}
                  disabled={running || busy || !desktop}
                  onChange={(event) =>
                    setRequireClientAuth(event.target.checked)
                  }
                />{" "}
                Require client profile authentication
              </label>
              {requireClientAuth && (
                <label>
                  Authenticated client profile{" "}
                  <select
                    value={selectedClientId}
                    disabled={running || busy || !desktop}
                    onChange={(event) =>
                      setSelectedClientId(event.target.value)
                    }
                  >
                    <option value="">Choose a configured client</option>
                    {clientProfiles.map((profile) => (
                      <option key={profile.id} value={profile.id}>
                        {profile.name}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {requireClientAuth && (
                <label>
                  <input
                    type="checkbox"
                    checked={enableHttpsInspection}
                    disabled={
                      running || busy || !desktop || !canRequestHttpsInspection
                    }
                    onChange={(event) =>
                      setEnableHttpsInspection(event.target.checked)
                    }
                  />{" "}
                  Explicitly enable TLS termination for authenticated
                  Development CONNECT destinations. HTTPS request contents are
                  not captured yet.
                </label>
              )}
              {running && proxyCredential && (
                <div className="proxy-credential" role="status">
                  <strong>
                    Authentication required for{" "}
                    {activeProxyClient?.name ?? "client"}
                  </strong>
                  <p>
                    Configure HTTP Basic proxy credentials with username{" "}
                    <code>{proxyCredential.profileId}</code> and this ephemeral
                    password:
                  </p>
                  <code className="trust-check-url">
                    {proxyCredential.token}
                  </code>
                  <p>
                    The password exists only for this proxy run and is not
                    included in captures.
                  </p>
                </div>
              )}
              {running && status?.clientProfileId && !proxyCredential && (
                <p className="error" role="alert">
                  This proxy run requires client authentication, but its
                  ephemeral password is no longer available in the UI. Stop and
                  restart the proxy to generate a new credential.
                </p>
              )}
              {running && status?.clientProfileId && tlsPreflight && (
                <div
                  className={`tls-preflight ${tlsPreflight.canEnableDevelopment ? "ready" : "blocked"}`}
                  role="status"
                >
                  <strong>
                    HTTPS inspection preflight: {tlsPreflight.state}
                  </strong>
                  <p>
                    {tlsPreflight.httpsInspectionActive
                      ? "Development CONNECT destinations now use the verified TLS transport bridge. Inner HTTP capture is not active yet."
                      : preflightMessage[tlsPreflight.state]}
                  </p>
                  {tlsPreflight.proofExpiresAt && (
                    <p>
                      Trust proof expires{" "}
                      {new Date(tlsPreflight.proofExpiresAt).toLocaleString()}.
                    </p>
                  )}
                  <p>
                    HTTPS inspection active:{" "}
                    {tlsPreflight.httpsInspectionActive ? "yes" : "no"}.
                  </p>
                </div>
              )}
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
                    onChange={(event) =>
                      setDevelopmentHosts(event.target.value)
                    }
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
                Responses have no per-body size cap and remain unredacted. JSON
                requests up to 1 MiB are redacted before temporary-disk storage;
                built-in secret keys are always protected and these additional
                paths support * for array/object members. Other request formats
                are not recorded. Body files are read in 64 KiB pages and are
                not encrypted at rest. Clear, eviction and normal app exit
                remove them; Stop keeps them available.
              </p>
            </div>
            <Traffic
              snapshot={snapshot}
              desktop={desktop}
              busy={busy}
              proxyCredential={proxyCredential}
              clear={() => void command("clear_traffic")}
              resolveBreakpoint={(id, status) =>
                void command("resolve_response_breakpoint", { id, status })
              }
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
              <dd>
                {status?.httpsInspection
                  ? "Enabled · Development TLS termination only"
                  : caStatus?.state === "ready"
                    ? "Disabled · local CA generated but not installed"
                    : "Disabled · no local CA generated"}
              </dd>
              <dt>HTTPS pass-through</dt>
              <dd>CONNECT supported · 5 minute tunnel limit</dd>
              <dt>Client authentication</dt>
              <dd>
                {status?.clientProfileId
                  ? `Required · ${status.clientProfileId}`
                  : "Optional · disabled for this proxy run"}
              </dd>
              <dt>Inspection preflight</dt>
              <dd>
                {tlsPreflight
                  ? `${tlsPreflight.state} · HTTPS inspection inactive`
                  : "Unavailable"}
              </dd>
              <dt>Production policy</dt>
              <dd>
                {status?.productionProtection
                  ? "Observation only; replay and modification unavailable"
                  : "Read-only by design"}
              </dd>
            </dl>
            <div className="settings-divider" />
            <h2>HTTPS inspection foundation</h2>
            <p>
              Generate an installation-specific development CA in your
              operating-system credential store. This does not install or trust
              the certificate, change system proxy settings, or enable HTTPS
              interception.
            </p>
            {caStatus?.state === "ready" ? (
              <div className="ca-panel">
                <dl>
                  <dt>State</dt>
                  <dd>Generated locally · not installed by Sippin Soda</dd>
                  <dt>SHA-256 fingerprint</dt>
                  <dd className="fingerprint">{caStatus.fingerprintSha256}</dd>
                  <dt>Created</dt>
                  <dd>
                    {caStatus.createdAt
                      ? new Date(caStatus.createdAt).toLocaleString()
                      : "Unavailable"}
                  </dd>
                  <dt>Expires</dt>
                  <dd>
                    {caStatus.expiresAt
                      ? new Date(caStatus.expiresAt).toLocaleString()
                      : "Unavailable"}
                  </dd>
                </dl>
                <button disabled={caBusy} onClick={() => void exportCa()}>
                  Export public certificate
                </button>
                <div className="trust-check-panel">
                  <h3>Verify client trust</h3>
                  <p>
                    Run a one-time local endpoint, then open its URL in the same
                    browser or runtime that will use the proxy. This verifies
                    only that client and does not enable HTTPS inspection.
                  </p>
                  <div className="client-profile-editor">
                    <label htmlFor="tls-client-profile">Client profile</label>
                    <div className="trust-check-actions">
                      <select
                        id="tls-client-profile"
                        value={selectedClientId}
                        disabled={
                          running ||
                          trustCheck?.state === "waiting" ||
                          trustCheckBusy
                        }
                        onChange={(event) =>
                          setSelectedClientId(event.target.value)
                        }
                      >
                        <option value="">Choose a configured client</option>
                        {clientProfiles.map((profile) => (
                          <option key={profile.id} value={profile.id}>
                            {profile.name}
                          </option>
                        ))}
                      </select>
                      <button
                        disabled={
                          !selectedClient ||
                          running ||
                          trustCheck?.state === "waiting" ||
                          trustCheckBusy
                        }
                        onClick={removeSelectedClient}
                      >
                        Remove profile
                      </button>
                    </div>
                    <div className="trust-check-actions">
                      <input
                        value={newClientName}
                        maxLength={80}
                        disabled={
                          running ||
                          trustCheck?.state === "waiting" ||
                          trustCheckBusy
                        }
                        aria-label="New client profile name"
                        placeholder="Chrome development profile"
                        onChange={(event) =>
                          setNewClientName(event.target.value)
                        }
                      />
                      <button
                        disabled={
                          !newClientName.trim() ||
                          running ||
                          trustCheck?.state === "waiting" ||
                          trustCheckBusy
                        }
                        onClick={addClientProfile}
                      >
                        Add profile
                      </button>
                    </div>
                    <p className="muted">
                      The profile records your chosen browser or runtime; it
                      does not identify a process automatically. A trust proof
                      cannot be reused for a different profile.
                    </p>
                  </div>
                  {trustCheck?.state === "waiting" ? (
                    <>
                      <p role="status">
                        Waiting for{" "}
                        {trustCheck.client?.name ?? "selected client"}.
                      </p>
                      <code className="trust-check-url">{trustCheck.url}</code>
                      <p>
                        Expires at{" "}
                        {trustCheck.expiresAt
                          ? new Date(trustCheck.expiresAt).toLocaleTimeString()
                          : "soon"}
                        .
                      </p>
                      <div className="trust-check-actions">
                        <button
                          disabled={trustCheckBusy}
                          onClick={() => void copyTrustCheckUrl()}
                        >
                          Copy temporary URL
                        </button>
                        <button
                          disabled={trustCheckBusy}
                          onClick={() =>
                            void trustCheckCommand("cancel_tls_trust_check")
                          }
                        >
                          Cancel check
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      {trustCheck?.state === "verified" && (
                        <p role="status">
                          Trust verified for{" "}
                          {trustCheck.client?.name ?? "this client"}
                          {trustCheck.verifiedAt
                            ? ` at ${new Date(trustCheck.verifiedAt).toLocaleTimeString()}`
                            : ""}
                          {trustCheck.expiresAt
                            ? `; proof expires ${new Date(trustCheck.expiresAt).toLocaleString()}`
                            : ""}
                          . HTTPS inspection remains disabled.
                        </p>
                      )}
                      {(trustCheck?.state === "failed" ||
                        trustCheck?.state === "expired") && (
                        <p className="error" role="alert">
                          {trustCheck.error}
                        </p>
                      )}
                      <label>
                        <input
                          type="checkbox"
                          checked={trustCheckConsent}
                          disabled={running || caBusy || trustCheckBusy}
                          onChange={(event) =>
                            setTrustCheckConsent(event.target.checked)
                          }
                        />{" "}
                        Start a 60-second loopback trust check. No certificate
                        or proxy setting will be installed or changed.
                      </label>
                      <button
                        disabled={
                          caBusy ||
                          trustCheckBusy ||
                          running ||
                          !trustCheckConsent ||
                          !selectedClient
                        }
                        onClick={() =>
                          void trustCheckCommand("start_tls_trust_check")
                        }
                      >
                        {trustCheckBusy
                          ? "Starting…"
                          : "Start local trust check"}
                      </button>
                    </>
                  )}
                </div>
                <label className="danger-confirmation">
                  <input
                    type="checkbox"
                    checked={caRemoveConfirmed}
                    disabled={caBusy}
                    onChange={(event) =>
                      setCaRemoveConfirmed(event.target.checked)
                    }
                  />{" "}
                  Remove the private key and certificate from credential
                  storage.
                </label>
                <button
                  disabled={caBusy || !caRemoveConfirmed}
                  onClick={() =>
                    void caCommand("remove_local_ca", { confirmed: true })
                  }
                >
                  Remove local CA material
                </button>
              </div>
            ) : (
              <div className="ca-panel">
                <label>
                  <input
                    type="checkbox"
                    checked={caConsent}
                    disabled={!desktop || caBusy}
                    onChange={(event) => setCaConsent(event.target.checked)}
                  />{" "}
                  I consent to generating a local CA private key in my
                  operating-system credential store. Nothing will be installed
                  into a trust store.
                </label>
                <button
                  disabled={!desktop || caBusy || !caConsent}
                  onClick={() =>
                    void caCommand("generate_local_ca", { consent: true })
                  }
                >
                  {caBusy ? "Generating…" : "Generate local CA"}
                </button>
              </div>
            )}
            {caMessage && <p role="status">{caMessage}</p>}
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
