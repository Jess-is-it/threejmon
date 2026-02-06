import { useEffect, useMemo, useState } from "react";
import { getJson } from "../api/http";
import { Panel } from "../ui/Panel";

type OpticalRow = {
  device_id?: string;
  name?: string;
  ip?: string;
  status?: "issue" | "monitor" | "stable" | string;
  rx?: number | null;
  tx?: number | null;
  samples?: number;
  last_check?: string;
  last_ts?: string;
  reasons?: string[];
  spark_points_window?: string;
  spark_points_window_large?: string;
  device_url?: string;
  rx_invalid?: boolean;
  tx_invalid?: boolean;
  tx_missing?: boolean;
  rx_reason?: string;
  tx_reason?: string;
};

type OpticalStatus = {
  total?: number;
  issue_total?: number;
  stable_total?: number;
  issue_rows?: OpticalRow[];
  stable_rows?: OpticalRow[];
  window_hours?: number;
  window_label?: string;
  pagination?: {
    limit?: number;
    limit_label?: string;
    options?: number[];
    issues?: { page?: number; pages?: number; has_prev?: boolean; has_next?: boolean; total?: number };
    stable?: { page?: number; pages?: number; has_prev?: boolean; has_next?: boolean; total?: number };
  };
  sort?: {
    issues?: { key?: string; dir?: "asc" | "desc" | string };
    stable?: { key?: string; dir?: "asc" | "desc" | string };
  };
  query?: string;
  rules?: Record<string, any>;
  chart?: Record<string, any>;
};

type OpticalSummary = {
  updated_at?: string;
  optical_job?: { last_run_at_ph?: string; last_success_at_ph?: string };
  optical_status?: OpticalStatus;
  optical_window_options?: [string, number][];
};

function formatDbm(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(2)} dBm`;
}

function badge(status: string) {
  const s = (status || "").toLowerCase();
  if (s === "issue") return "bg-red-500/15 text-red-200 border-red-500/20";
  if (s === "monitor") return "bg-amber-500/15 text-amber-200 border-amber-500/20";
  return "bg-emerald-500/15 text-emerald-200 border-emerald-500/20";
}

function nextSort(currentKey: string, currentDir: string, clickedKey: string) {
  if (currentKey !== clickedKey) return { key: clickedKey, dir: "desc" as const };
  return { key: clickedKey, dir: (currentDir || "desc") === "desc" ? ("asc" as const) : ("desc" as const) };
}

function Sparkline(props: { points?: string; width: number; height: number }) {
  const pts = (props.points || "").trim();
  return (
    <svg
      viewBox={`0 0 ${props.width} ${props.height}`}
      width={props.width}
      height={props.height}
      className="block"
      aria-hidden="true"
    >
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="2" className="text-sky-300" />
    </svg>
  );
}

export function OpticalPage() {
  const [view, setView] = useState<"status" | "settings">("status");
  const [tab, setTab] = useState<"issues" | "stable">("issues");
  const [windowHours, setWindowHours] = useState<number>(24);
  const [limit, setLimit] = useState<number>(50);
  const [queryDraft, setQueryDraft] = useState<string>("");
  const [query, setQuery] = useState<string>("");
  const [issuesPage, setIssuesPage] = useState<number>(1);
  const [stablePage, setStablePage] = useState<number>(1);
  const [issuesSort, setIssuesSort] = useState<{ key: string; dir: "asc" | "desc" }>({ key: "", dir: "desc" });
  const [stableSort, setStableSort] = useState<{ key: string; dir: "asc" | "desc" }>({ key: "", dir: "desc" });
  const [data, setData] = useState<OpticalSummary | null>(null);
  const [error, setError] = useState("");
  const [height, setHeight] = useState<number>(900);
  const [modalRow, setModalRow] = useState<OpticalRow | null>(null);

  const requestUrl = useMemo(() => {
    const params = new URLSearchParams();
    params.set("window", String(windowHours));
    params.set("limit", String(limit));
    params.set("issues_page", String(issuesPage));
    params.set("stable_page", String(stablePage));
    if (issuesSort.key) {
      params.set("issues_sort", issuesSort.key);
      params.set("issues_dir", issuesSort.dir);
    }
    if (stableSort.key) {
      params.set("stable_sort", stableSort.key);
      params.set("stable_dir", stableSort.dir);
    }
    if (query.trim()) params.set("q", query.trim());
    return `/api/optical/summary?${params.toString()}`;
  }, [windowHours, limit, issuesPage, stablePage, issuesSort, stableSort, query]);

  useEffect(() => {
    const onResize = () => setHeight(Math.max(window.innerHeight - 220, 560));
    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    let stopped = false;
    const tick = async () => {
      try {
        const json = await getJson<OpticalSummary>(requestUrl);
        if (stopped) return;
        setData(json);
        setError("");
      } catch (e: any) {
        if (stopped) return;
        setError(e?.message || "Failed to load optical summary.");
      }
    };
    tick();
    const id = window.setInterval(tick, 5000);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
  }, [requestUrl]);

  const optical = data?.optical_status;
  const counts = { issues: Number(optical?.issue_total || 0), stable: Number(optical?.stable_total || 0) };

  const rows = useMemo(() => {
    const all = (tab === "issues" ? optical?.issue_rows : optical?.stable_rows) || [];
    return all as OpticalRow[];
  }, [optical, tab]);

  const pageMeta = tab === "issues" ? optical?.pagination?.issues : optical?.pagination?.stable;
  const windowOptions = (data?.optical_window_options || []) as [string, number][];
  const limitOptions = (optical?.pagination?.options || [50, 100, 200, 500, 1000]) as number[];

  const setActiveSort = (key: string) => {
    if (tab === "issues") {
      setIssuesPage(1);
      setIssuesSort((cur) => nextSort(cur.key, cur.dir, key));
    } else {
      setStablePage(1);
      setStableSort((cur) => nextSort(cur.key, cur.dir, key));
    }
  };

  const commitQuery = () => {
    setIssuesPage(1);
    setStablePage(1);
    setQuery(queryDraft.trim());
  };

  return (
    <div className="space-y-6">
      <Panel
        title="Optical Monitoring"
        right={
          <span className="text-slate-400">
            Updated: {data?.updated_at || "n/a"}
            {data?.optical_job?.last_success_at_ph ? ` · Last success: ${data.optical_job.last_success_at_ph}` : ""}
          </span>
        }
      >
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              view === "status"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setView("status")}
          >
            Status
          </button>
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              view === "settings"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setView("settings")}
          >
            Settings
          </button>
          <div className="ml-auto text-xs text-slate-500">Settings are rendered from the legacy page for now (embedded).</div>
        </div>

        {view === "settings" ? (
          <div className="rounded-lg border border-white/10 overflow-hidden bg-black/20">
            <iframe title="Optical Settings" src="/settings/optical?embed=1" style={{ width: "100%", height }} className="block w-full" />
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <button
                className={[
                  "rounded-lg px-3 py-2 text-sm font-medium border",
                  tab === "issues"
                    ? "border-white/10 bg-white/10 text-white"
                    : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
                ].join(" ")}
                onClick={() => setTab("issues")}
              >
                Issues ({counts.issues})
              </button>
              <button
                className={[
                  "rounded-lg px-3 py-2 text-sm font-medium border",
                  tab === "stable"
                    ? "border-white/10 bg-white/10 text-white"
                    : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
                ].join(" ")}
                onClick={() => setTab("stable")}
              >
                Stable/Monitor ({counts.stable})
              </button>

              <div className="ml-auto flex flex-wrap items-center gap-2">
                <select
                  className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
                  value={String(windowHours)}
                  onChange={(e) => {
                    setIssuesPage(1);
                    setStablePage(1);
                    setWindowHours(Number(e.target.value || 24));
                  }}
                >
                  {windowOptions.length ? (
                    windowOptions.map(([label, hours]) => (
                      <option key={label} value={String(hours)}>
                        Window: {label}
                      </option>
                    ))
                  ) : (
                    <option value="24">Window: 1D</option>
                  )}
                </select>
                <select
                  className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
                  value={String(limit)}
                  onChange={(e) => {
                    setIssuesPage(1);
                    setStablePage(1);
                    setLimit(Number(e.target.value || 50));
                  }}
                >
                  {limitOptions.map((n) => (
                    <option key={n} value={String(n)}>
                      Limit: {n}
                    </option>
                  ))}
                  <option value="0">Limit: ALL</option>
                </select>
                <div className="w-full sm:w-72">
                  <input
                    className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
                    placeholder="Search (press Enter)"
                    value={queryDraft}
                    onChange={(e) => setQueryDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitQuery();
                    }}
                  />
                </div>
              </div>
            </div>

            {error ? <div className="mt-3 text-sm text-red-300">{error}</div> : null}

            <div className="mt-4 overflow-auto rounded-lg border border-white/10">
              <table className="min-w-[1100px] w-full text-sm">
                <thead className="bg-slate-950/60">
                  <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("name")}>
                      Customer
                    </th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("ip")}>
                      IP
                    </th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("status")}>
                      Status
                    </th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("rx")}>
                      RX
                    </th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("tx")}>
                      TX
                    </th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("samples")}>
                      Samples
                    </th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("last_check_at")}>
                      Last Check
                    </th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("reason")}>
                      Reason
                    </th>
                    <th className="px-3 py-2">Trend</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.length ? (
                    rows.map((r, idx) => {
                      const name = r.name || r.device_id || "";
                      const rxLabel = r.rx_invalid ? "Missing/Unrealistic" : formatDbm(r.rx);
                      const txLabel = r.tx_missing || r.tx_invalid ? "Missing/Unrealistic" : formatDbm(r.tx);
                      return (
                        <tr key={`${r.device_id || ""}-${idx}`} className="border-t border-white/5">
                          <td className="px-3 py-2 font-semibold">
                            <div className="flex items-center gap-2">
                              <span>{name}</span>
                              {r.device_url ? (
                                <a className="text-sky-300 hover:underline text-xs" href={r.device_url} target="_blank" rel="noreferrer">
                                  GenieACS →
                                </a>
                              ) : null}
                            </div>
                            <div className="text-xs text-slate-500">{r.device_id || ""}</div>
                          </td>
                          <td className="px-3 py-2 text-slate-300">{r.ip || "—"}</td>
                          <td className="px-3 py-2">
                            <span className={["inline-flex items-center rounded-full border px-2 py-1 text-xs", badge(String(r.status || ""))].join(" ")}>
                              {String(r.status || "").toUpperCase() || "—"}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-slate-300">
                            <div>{rxLabel}</div>
                            {r.rx_reason ? <div className="text-xs text-slate-500">{r.rx_reason}</div> : null}
                          </td>
                          <td className="px-3 py-2 text-slate-300">
                            <div>{txLabel}</div>
                            {r.tx_reason ? <div className="text-xs text-slate-500">{r.tx_reason}</div> : null}
                          </td>
                          <td className="px-3 py-2 text-slate-300">{Number(r.samples || 0)}</td>
                          <td className="px-3 py-2 text-slate-300">{r.last_check || "—"}</td>
                          <td className="px-3 py-2 text-slate-400">{(r.reasons || []).join(", ") || "—"}</td>
                          <td className="px-3 py-2">
                            <button
                              className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-slate-200 hover:bg-white/10"
                              onClick={() => setModalRow(r)}
                              disabled={!String(r.spark_points_window_large || "").trim()}
                              title="Open trend"
                            >
                              <Sparkline points={r.spark_points_window} width={120} height={30} />
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr className="border-t border-white/5">
                      <td className="px-3 py-3 text-slate-400" colSpan={9}>
                        {data ? "No rows." : "Loading…"}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="mt-3 flex items-center justify-between gap-2 text-sm text-slate-300">
              <div>
                Page {Number(pageMeta?.page || 1)} / {Number(pageMeta?.pages || 1)} · Total {Number(pageMeta?.total || 0)}
              </div>
              <div className="flex items-center gap-2">
                <button
                  className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10 disabled:opacity-40"
                  onClick={() => (tab === "issues" ? setIssuesPage((p) => Math.max(p - 1, 1)) : setStablePage((p) => Math.max(p - 1, 1)))}
                  disabled={!pageMeta?.has_prev}
                >
                  Prev
                </button>
                <button
                  className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10 disabled:opacity-40"
                  onClick={() => (tab === "issues" ? setIssuesPage((p) => p + 1) : setStablePage((p) => p + 1))}
                  disabled={!pageMeta?.has_next}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>

      {modalRow ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          role="dialog"
          aria-modal="true"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setModalRow(null);
          }}
        >
          <div className="w-full max-w-4xl rounded-xl border border-white/10 bg-slate-950 shadow-xl">
            <div className="flex items-start justify-between gap-3 border-b border-white/10 p-4">
              <div>
                <div className="text-lg font-semibold text-white">{modalRow.name || modalRow.device_id || "Trend"}</div>
                <div className="text-sm text-slate-400">
                  {modalRow.ip ? `IP: ${modalRow.ip} · ` : ""}
                  RX: {modalRow.rx_invalid ? "Missing/Unrealistic" : formatDbm(modalRow.rx)} · TX:{" "}
                  {modalRow.tx_missing || modalRow.tx_invalid ? "Missing/Unrealistic" : formatDbm(modalRow.tx)}
                </div>
              </div>
              <button
                className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10"
                onClick={() => setModalRow(null)}
              >
                Close
              </button>
            </div>
            <div className="p-4">
              <div className="rounded-lg border border-white/10 bg-black/20 p-3 text-slate-200">
                <Sparkline points={modalRow.spark_points_window_large} width={640} height={200} />
              </div>
              {modalRow.device_url ? (
                <div className="mt-3">
                  <a className="text-sky-300 hover:underline" href={modalRow.device_url} target="_blank" rel="noreferrer">
                    Open device in GenieACS →
                  </a>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

