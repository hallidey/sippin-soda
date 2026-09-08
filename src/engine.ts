import { useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type Capture = {
  id: number;
  method: string;
  target: string;
  startedAt: number;
  status: number | null;
  phase: "pending" | "complete" | "error";
  durationMs: number;
  requestBytes: number;
  responseBytes: number;
  requestHeaders: [string, string][];
  responseHeaders: [string, string][];
  error: string | null;
};

export type Snapshot = {
  revision: number;
  status: {
    phase: "stopped" | "running";
    listenAddress: string;
    captures: number;
    httpsInspection: boolean;
    productionProtection: boolean;
    evictedCaptures: number;
    rejectedConnections: number;
  };
  traffic: Capture[];
};

export function useEngine() {
  const desktop = isTauri();
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const accept = (next: Snapshot) =>
    setSnapshot((previous) =>
      !previous || next.revision >= previous.revision ? next : previous,
    );

  useEffect(() => {
    if (!desktop) return;
    let alive = true;
    let unsubscribe: (() => void) | undefined;
    const refresh = async () => {
      try {
        const next = await invoke<Snapshot>("engine_snapshot");
        if (alive) accept(next);
      } catch {
        if (alive)
          setError(
            "Unable to read the local engine. Restart the desktop application.",
          );
      }
    };
    void listen("engine-changed", () => void refresh())
      .then((unlisten) => {
        if (!alive) {
          unlisten();
          return;
        }
        unsubscribe = unlisten;
        void refresh();
      })
      .catch(() => {
        if (alive) setError("Unable to subscribe to local engine updates.");
      });
    return () => {
      alive = false;
      unsubscribe?.();
    };
  }, [desktop]);

  const command = async (name: string, args?: Record<string, unknown>) => {
    setBusy(true);
    setError("");
    try {
      accept(await invoke<Snapshot>(name, args));
    } catch (cause) {
      setError(
        typeof cause === "string" ? cause : "The engine command failed.",
      );
    } finally {
      setBusy(false);
    }
  };
  return { desktop, snapshot, error, busy, command };
}
