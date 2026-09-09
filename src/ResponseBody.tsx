import { useEffect, useRef, useState } from "react";
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
type SearchStep = {
  found: number | null;
  nextOffset: number;
  scannedTo: number;
  done: boolean;
};
type JsonStatus = { state: string; error: string | null };

export function ResponseBody({
  id,
  desktop,
  recordingError,
  pending,
  direction = "response",
}: {
  id: number;
  desktop: boolean;
  recordingError: string | null;
  pending: boolean;
  direction?: "request" | "response";
}) {
  const command = (suffix: string) => `${direction}_${suffix}`;
  const title = direction === "request" ? "Request body" : "Response body";
  const [offset, setOffset] = useState(0);
  const [jump, setJump] = useState("0");
  const [page, setPage] = useState<Page | null>(null);
  const [error, setError] = useState("");
  const [hex, setHex] = useState(false);
  const [json, setJson] = useState(false);
  const [jsonStatus, setJsonStatus] = useState<JsonStatus>({
    state: "idle",
    error: null,
  });
  const [needle, setNeedle] = useState("");
  const [found, setFound] = useState<number | null>(null);
  const [searchMessage, setSearchMessage] = useState("");
  const [searching, setSearching] = useState(false);
  const searchRun = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      searchRun.current += 1;
    };
  }, []);
  useEffect(() => {
    if (jsonStatus.state !== "building") return;
    let active = true;
    const timer = setInterval(() => {
      void invoke<JsonStatus>(command("json_view"), {
        id,
        start: false,
        cancel: false,
      })
        .then((status) => {
          if (!active) return;
          setJsonStatus(status);
          if (status.state === "ready") {
            setJson(true);
            setHex(false);
            setOffset(0);
            setJump("0");
          }
        })
        .catch((cause) => {
          if (active) setJsonStatus({ state: "error", error: String(cause) });
        });
    }, 750);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [id, jsonStatus.state]);
  const prepareJson = async () => {
    try {
      const status = await invoke<JsonStatus>(command("json_view"), {
        id,
        start: true,
        cancel: false,
      });
      if (!mounted.current) return;
      setJsonStatus(status);
      if (status.state === "ready") {
        setJson(true);
        setHex(false);
        go(0);
      }
    } catch (cause) {
      if (mounted.current)
        setJsonStatus({ state: "error", error: String(cause) });
    }
  };
  const cancelSearch = () => {
    searchRun.current += 1;
    setSearching(false);
    setSearchMessage("Search cancelled.");
  };
  const search = async (start: number) => {
    const run = ++searchRun.current;
    setSearching(true);
    setSearchMessage("Searching recorded bytes…");
    try {
      // Freeze the range at click time. New streamed bytes require a new search.
      const raw = await invoke<Page>(command("body_page"), {
        id,
        offset: 0,
        length: 1,
      });
      let cursor = start;
      while (run === searchRun.current && mounted.current) {
        const result = await invoke<SearchStep>(`search_${direction}_body`, {
          id,
          needle,
          start: cursor,
          end: raw.total,
        });
        if (run !== searchRun.current || !mounted.current) return;
        if (result.found !== null) {
          setFound(result.found);
          setJson(false);
          setHex(false);
          go(result.found);
          setSearchMessage(
            `Match at raw byte ${result.found.toLocaleString()}. Searched captured bytes; capture state: ${raw.state}.`,
          );
          break;
        }
        setSearchMessage(
          `Searched ${result.scannedTo.toLocaleString()} / ${raw.total.toLocaleString()} bytes…`,
        );
        if (result.done) {
          setSearchMessage(
            `No ${start ? "further " : ""}match in ${raw.total.toLocaleString()} recorded bytes (${raw.state}).`,
          );
          break;
        }
        cursor = result.nextOffset;
      }
    } catch (cause) {
      if (run === searchRun.current && mounted.current)
        setSearchMessage(String(cause));
    } finally {
      if (run === searchRun.current && mounted.current) setSearching(false);
    }
  };
  useEffect(() => {
    if (!desktop || recordingError) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    setPage(null);
    setError("");
    const read = async () => {
      try {
        const next = await invoke<Page>(
          json ? command("json_page") : command("body_page"),
          {
            id,
            offset,
            length: PAGE,
          },
        );
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
  }, [id, offset, desktop, recordingError, pending, json, direction]);
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
    <section className="body-view" aria-label={title}>
      <h3>{title}</h3>
      <p>
        {direction === "request"
          ? "Redacted JSON inspection copy · original request bytes were forwarded unchanged."
          : "Unredacted local capture · text is interpreted as UTF-8. Hex preserves every byte; UTF-8 characters split at page boundaries may display as replacement characters."}
      </p>
      <div className="body-toolbar">
        <label>
          Find in full body{" "}
          <input
            value={needle}
            disabled={searching}
            onChange={(event) => {
              setNeedle(event.target.value);
              setFound(null);
              setSearchMessage("");
            }}
            placeholder="Exact text, case-sensitive"
          />
        </label>
        <button
          disabled={
            !desktop ||
            searching ||
            !needle ||
            new TextEncoder().encode(needle).length > 4096 ||
            jsonStatus.state === "building"
          }
          onClick={() => void search(0)}
        >
          Find from start
        </button>
        <button
          disabled={
            searching || found === null || jsonStatus.state === "building"
          }
          onClick={() => void search((found ?? -1) + 1)}
        >
          Find next
        </button>
        {searching && <button onClick={cancelSearch}>Cancel search</button>}
      </div>
      {searchMessage && <p role="status">{searchMessage}</p>}
      <div className="body-toolbar">
        <button
          aria-pressed={!json}
          onClick={() => {
            setJson(false);
            go(0);
          }}
        >
          Original bytes
        </button>
        <button
          aria-pressed={json}
          disabled={
            !desktop ||
            searching ||
            jsonStatus.state === "building" ||
            (!json && page?.state !== "complete")
          }
          onClick={() => void prepareJson()}
        >
          JSON layout
        </button>
        {jsonStatus.state === "building" && (
          <>
            <span>Preparing paged JSON on disk…</span>
            <button
              onClick={() =>
                void invoke(command("json_view"), {
                  id,
                  start: false,
                  cancel: true,
                }).catch((cause) =>
                  setJsonStatus({ state: "error", error: String(cause) }),
                )
              }
            >
              Cancel layout
            </button>
          </>
        )}
      </div>
      {jsonStatus.error && <p role="status">{jsonStatus.error}</p>}
      {json && (
        <p>
          Formatted JSON · offsets refer to the formatted view. Search always
          uses original decoded bytes. This temporary view shares the session
          disk budget.
        </p>
      )}
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
            {hex ? (
              hexText
            ) : !json &&
              found === offset &&
              text.startsWith(needle) &&
              needle ? (
              <>
                <mark>{needle}</mark>
                {text.slice(needle.length)}
              </>
            ) : (
              text || "Empty body / waiting for bytes."
            )}
          </pre>
        </>
      )}
    </section>
  );
}
