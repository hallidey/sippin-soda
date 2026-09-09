import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type Page = {
  offset: number;
  total: number;
  bytes: number[];
  state: string;
  error: string | null;
  encoding: string;
};
const PAGE = 65536;

export function ResponseBody({
  id,
  desktop,
  recordingError,
  pending,
}: {
  id: number;
  desktop: boolean;
  recordingError: string | null;
  pending: boolean;
}) {
  const [offset, setOffset] = useState(0);
  const [jump, setJump] = useState("0");
  const [page, setPage] = useState<Page | null>(null);
  const [error, setError] = useState("");
  const [hex, setHex] = useState(false);
  useEffect(() => {
    if (!desktop || recordingError) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    setPage(null);
    setError("");
    const read = async () => {
      try {
        const next = await invoke<Page>("response_body_page", {
          id,
          offset,
          length: PAGE,
        });
        if (!alive) return;
        setPage(next);
        setError("");
        if (next.state === "recording")
          timer = setTimeout(() => void read(), 1000);
      } catch (cause) {
        if (alive) {
          setError(String(cause));
          if (pending) timer = setTimeout(() => void read(), 1000);
        }
      }
    };
    void read();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [id, offset, desktop, recordingError, pending]);
  const go = (next: number) => {
    setOffset(next);
    setJump(String(next));
  };
  const text = page
    ? new TextDecoder("utf-8").decode(new Uint8Array(page.bytes))
    : "";
  const hexText =
    page && hex
      ? Array.from({ length: Math.ceil(page.bytes.length / 16) }, (_, row) => {
          const bytes = page.bytes.slice(row * 16, row * 16 + 16);
          return `${(page.offset + row * 16).toString(16).padStart(12, "0")}  ${bytes.map((byte) => byte.toString(16).padStart(2, "0")).join(" ")}`;
        }).join("\n")
      : "";
  return (
    <section className="body-view" aria-label="Response body">
      <h3>Response body</h3>
      <p>
        Unredacted local capture · text is interpreted as UTF-8. Hex preserves
        every byte; UTF-8 characters split at page boundaries may display as
        replacement characters.
      </p>
      {recordingError || error ? (
        <p role="status">{recordingError || error}</p>
      ) : !page ? (
        <p>Reading body…</p>
      ) : (
        <>
          <p>
            {page.total.toLocaleString()} decoded bytes · {page.state} ·
            encoding: {page.encoding || "identity"}
          </p>
          {page.error && (
            <p className="error" role="status">
              {page.error}
            </p>
          )}
          <div className="body-toolbar">
            <button onClick={() => go(0)} disabled={!offset}>
              First
            </button>
            <button
              onClick={() => go(Math.max(0, offset - PAGE))}
              disabled={!offset}
            >
              Previous
            </button>
            <button
              onClick={() => go(offset + PAGE)}
              disabled={offset + PAGE >= page.total}
            >
              Next
            </button>
            <button
              onClick={() =>
                go(Math.max(0, Math.floor((page.total - 1) / PAGE) * PAGE))
              }
              disabled={!page.total}
            >
              Last
            </button>
            <label>
              Byte offset{" "}
              <input
                inputMode="numeric"
                value={jump}
                onChange={(event) => setJump(event.target.value)}
              />
            </label>
            <button
              disabled={
                !/^\d+$/.test(jump) ||
                !Number.isSafeInteger(Number(jump)) ||
                Number(jump) > page.total
              }
              onClick={() => go(Number(jump))}
            >
              Go
            </button>
            <label>
              <input
                type="checkbox"
                checked={hex}
                onChange={(event) => setHex(event.target.checked)}
              />{" "}
              Hex
            </label>
          </div>
          <p>
            Bytes {offset.toLocaleString()}–
            {(offset + page.bytes.length).toLocaleString()} (end exclusive).
            Only this page is loaded into the interface.
          </p>
          <pre className="body-content" tabIndex={0}>
            {hex ? hexText : text || "Empty body / waiting for bytes."}
          </pre>
        </>
      )}
    </section>
  );
}
