import { useEffect, useMemo, useState } from "react";
import { getJson } from "../api/http";
import { Panel } from "../ui/Panel";

type PingRow = {
  id?: string;
  name?: string;
  ip?: string;
  status?: "down" | "monitor" | "up" | "pending" | string;
  loss?: number | null;
  avg_ms?: number | null;
  rto_pct?: number | null;
  uptime_pct?: number | null;
  streak?: number | null;
  down_for?: string;
  down_seconds?: number;
  last_check?: string;
  last_check_at?: string;
  reasons?: string[];
  spark_points_24h?: string;
  spark_points_24h_large?: string;
  pending?: boolean;
};

type PingStatus = {
  total?: number;
  issue_total?: number;
  stable_total?: number;
  pending_total?: number;
  issue_rows?: PingRow[];
  stable_rows?: PingRow[];
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
};

type Summary = {
  updated_at?: string;
  accounts_ping_job?: { last_run_at_ph?: string; last_success_at_ph?: string };
  accounts_ping_status?: PingStatus;
  accounts_ping_window_options?: [string, number][];
};

function badge(status: string) {
  const s = (status || "").toLowerCase();
  if (s === "down") return "bg-red-500/15 text-red-200 border-red-500/20";
  if (s === "monitor") return "bg-amber-500/15 text-amber-200 border-amber-500/20";
  if (s === "pending") return "bg-slate-500/15 text-slate-200 border-white/10";
  return "bg-emerald-500/15 text-emerald-200 border-emerald-500/20";
}

function formatPct(v: number | null | undefined, digits = 1) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(digits)}%`;
}

function formatMs(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(0)} ms`;
}

function Sparkline(props: { points?: string; width: number; height: number }) {
  const pts = (props.points || "").trim();
  return (
    <svg viewBox={`0 0 ${props.width} ${props.height}`} width={props.width} height={props.height} className="block">
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="2" className="text-sky-300" />
    </svg>
  );
}

function nextSort(currentKey: string, currentDir: string, clickedKey: string) {
  if (currentKey !== clickedKey) return { key: clickedKey, dir: "desc" as const };
  return { key: clickedKey, dir: (currentDir || "desc") === "desc" ? ("asc" as const) : ("desc" as const) };
}

export function AccountsPingPage() {
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
  const [data, setData] = useState<Summary | null>(null);
  const [error, setError] = useState("");
  const [height, setHeight] = useState<number>(900);
  const [modalRow, setModalRow] = useState<PingRow | null>(null);

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
    return `/api/accounts-ping/summary?${params.toString()}`;
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
        const json = await getJson<Summary>(requestUrl);
        if (stopped) return;
        setData(json);
        setError("");
      } catch (e: any) {
        if (stopped) return;
        setError(e?.message || "Failed to load accounts ping summary.");
      }
    };
    tick();
    const id = window.setInterval(tick, 5000);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
  }, [requestUrl]);

  const status = data?.accounts_ping_status;
  const counts = {
    issues: Number(status?.issue_total || 0),
    stable: Number(status?.stable_total || 0),
    pending: Number(status?.pending_total || 0),
  };

  const rows = useMemo(() => {
    const all = (tab === "issues" ? status?.issue_rows : status?.stable_rows) || [];
    return all as PingRow[];
  }, [status, tab]);

  const pageMeta = tab === "issues" ? status?.pagination?.issues : status?.pagination?.stable;
  const windowOptions = (data?.accounts_ping_window_options || []) as [string, number][];
  const limitOptions = (status?.pagination?.options || [50, 100, 200, 500, 1000]) as number[];

  const commitQuery = () => {
    setIssuesPage(1);
    setStablePage(1);
    setQuery(queryDraft.trim());
  };

  const setActiveSort = (key: string) => {
    if (tab === "issues") {
      setIssuesPage(1);
      setIssuesSort((cur) => nextSort(cur.key, cur.dir, key));
    } else {
      setStablePage(1);
      setStableSort((cur) => nextSort(cur.key, cur.dir, key));
    }
  };

  return (
    <div className="space-y-6">
      <Panel
        title="Accounts Ping"
        subtitle="Account reachability + loss/latency and 24H stability sparklines."
        right={
          <span className="text-slate-400">
            Updated: {data?.updated_at || "n/a"}
            {data?.accounts_ping_job?.last_success_at_ph ? ` · Last success: ${data.accounts_ping_job.last_success_at_ph}` : ""}
          </span>
        }
      >
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <button
            className={[
              "rounded-xl px-3 py-2 text-sm font-medium border",
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
              "rounded-xl px-3 py-2 text-sm font-medium border",
              view === "settings"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setView("settings")}
          >
            Settings
          </button>
          <div className="ml-auto text-xs text-slate-500">Settings are embedded from the legacy page for now.</div>
        </div>

        {view === "settings" ? (
          <div className="rounded-2xl border border-white/10 overflow-hidden bg-black/20">
            <iframe title="Accounts Ping Settings" src="/settings/accounts-ping?embed=1" style={{ width: "100%", height }} className="block w-full" />
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <button
                className={[
                  "rounded-xl px-3 py-2 text-sm font-medium border",
                  tab === "issues"
                    ? "border-white/10 bg-white/10 text-white"
                    : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
                ].join(" ")}
                onClick={() => setTab("issues")}
              >
                Issues/Monitor ({counts.issues})
              </button>
              <button
                className={[
                  "rounded-xl px-3 py-2 text-sm font-medium border",
                  tab === "stable"
                    ? "border-white/10 bg-white/10 text-white"
                    : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
                ].join(" ")}
                onClick={() => setTab("stable")}
              >
                Stable ({counts.stable}){counts.pending ? ` · Pending ${counts.pending}` : ""}
              </button>

              <div className="ml-auto flex flex-wrap items-center gap-2">
                <select
                  className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
                  value={String(windowHours)}
                  onChange={(e) => {
                    setIssuesPage(1);
                    setStablePage(1);
                    setWindowHours(Number(e.target.value || 24));
                  }}
                >
                  {(windowOptions.length ? windowOptions : ([
                    ["6H", 6],
                    ["12H", 12],
                    ["1D", 24],
                    ["7D", 168],
                    ["15D", 360],
                    ["30D", 720],
                  ] as [string, number][])).map(([label, hours]) => (
                    <option key={label} value={String(hours)}>
                      Window: {label}
                    </option>
                  ))}
                </select>
                <select
                  className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
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
                    className="w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
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

            <div className="mt-4 overflow-auto rounded-2xl border border-white/10">
              <table className="min-w-[1280px] w-full text-sm">
                <thead className="bg-slate-950/60">
                  <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("name")}>Account</th>
                    <th className="px-3 py-2">IP</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("status")}>Status</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("loss")}>Loss</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("avg_ms")}>Latency</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("rto_pct")}>Fail %</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("uptime_pct")}>Uptime %</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("streak")}>Streak</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("down_seconds")}>Down For</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("last_check_at")}>Last Check</th>
                    <th className="px-3 py-2 cursor-pointer select-none" onClick={() => setActiveSort("reason")}>Reason</th>
                    <th className="px-3 py-2">24H Trend</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.length ? (
                    rows.map((r, idx) => (
                      <tr key={`${r.id || ""}-${idx}`} className="border-t border-white/5">
                        <td className="px-3 py-2 font-semibold text-white">{r.name || r.id || "—"}</td>
                        <td className="px-3 py-2 text-slate-300">{r.ip || "—"}</td>
                        <td className="px-3 py-2">
                          <span className={["inline-flex items-center rounded-full border px-2 py-1 text-xs", badge(String(r.status || ""))].join(" ")}>
                            {String(r.status || "unknown").toUpperCase()}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-slate-300">{r.pending ? "—" : formatPct(r.loss, 1)}</td>
                        <td className="px-3 py-2 text-slate-300">{r.pending ? "—" : formatMs(r.avg_ms)}</td>
                        <td className="px-3 py-2 text-slate-300">{r.pending ? "—" : formatPct(r.rto_pct, 2)}</td>
                        <td className="px-3 py-2 text-slate-300">{r.pending ? "—" : formatPct(r.uptime_pct, 2)}</td>
                        <td className="px-3 py-2 text-slate-300">{Number(r.streak || 0)}</td>
                        <td className="px-3 py-2 text-slate-300">{r.down_for || "—"}</td>
                        <td className="px-3 py-2 text-slate-300">{r.last_check || "—"}</td>
                        <td className="px-3 py-2 text-slate-400">{(r.reasons || []).join("; ") || "—"}</td>
                        <td className="px-3 py-2">
                          <button
                            className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-slate-200 hover:bg-white/10 disabled:opacity-40"
                            onClick={() => setModalRow(r)}
                            disabled={!String(r.spark_points_24h_large || "").trim()}
                            title="Open 24H trend"
                          >
                            <Sparkline points={r.spark_points_24h} width={140} height={28} />
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr className="border-t border-white/5">
                      <td className="px-3 py-3 text-slate-400" colSpan={12}>
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
                  className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10 disabled:opacity-40"
                  onClick={() => (tab === "issues" ? setIssuesPage((p) => Math.max(p - 1, 1)) : setStablePage((p) => Math.max(p - 1, 1)))}
                  disabled={!pageMeta?.has_prev}
                >
                  Prev
                </button>
                <button
                  className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10 disabled:opacity-40"
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
          <div className="w-full max-w-4xl rounded-2xl border border-white/10 bg-slate-950 shadow-xl">
            <div className="flex items-start justify-between gap-3 border-b border-white/10 p-4">
              <div>
                <div className="text-lg font-semibold text-white">{modalRow.name || modalRow.id || "24H Trend"}</div>
                <div className="text-sm text-slate-400">{modalRow.ip ? `IP: ${modalRow.ip}` : ""}</div>
              </div>
              <button
                className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10"
                onClick={() => setModalRow(null)}
              >
                Close
              </button>
            </div>
            <div className="p-4">
              <div className="rounded-xl border border-white/10 bg-black/20 p-3 text-slate-200">
                <Sparkline points={modalRow.spark_points_24h_large} width={640} height={200} />
                <div className="mt-2 text-xs text-slate-400">Uptime % buckets over the last 24H (based on rollups).</div>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

