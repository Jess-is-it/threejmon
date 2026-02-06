import { useEffect, useMemo, useState } from "react";
import { getJson } from "../api/http";
import { Panel } from "../ui/Panel";

type SurvRow = {
  pppoe: string;
  ip?: string;
  ok?: boolean;
  loss?: number | null;
  avg_ms?: number | null;
  added_mode?: string;
  added_at_iso?: string;
  last_check?: string;
  down_for?: string;
  optical_rx?: number | null;
  optical_last?: string;
};

type SurvSummary = {
  updated_at?: string;
  stable_window_days?: number;
  counts?: {
    under_total?: number;
    under_auto?: number;
    under_manual?: number;
    level2_total?: number;
  };
  rows?: { under?: SurvRow[]; level2?: SurvRow[] };
};

type SurvHistoryRow = {
  id?: string | number;
  pppoe?: string;
  source?: string;
  last_ip?: string;
  last_state?: string;
  observed_count?: number;
  end_reason?: string;
  started_at_ph?: string;
  ended_at_ph?: string;
  active?: boolean;
  currently_active?: boolean;
};

type SurvHistory = {
  ok?: boolean;
  query?: string;
  page?: number;
  pages?: number;
  total?: number;
  limit?: number;
  rows?: SurvHistoryRow[];
};

function formatLoss(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "n/a";
  return `${n.toFixed(1)}%`;
}

function formatMs(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "n/a";
  return `${n.toFixed(1)}ms`;
}

function formatRx(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "n/a";
  return `${n.toFixed(2)} dBm`;
}

function underForFromIso(iso?: string) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "—";
  const seconds = Math.max((Date.now() - t) / 1000, 0);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

async function postForm(url: string, fields: Record<string, string>) {
  const body = new URLSearchParams();
  Object.entries(fields).forEach(([k, v]) => body.set(k, v));
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "text/html" },
    body: body.toString(),
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
}

export function SurveillancePage() {
  const [tab, setTab] = useState<"under" | "level2" | "history" | "settings">("under");
  const [summary, setSummary] = useState<SurvSummary | null>(null);
  const [history, setHistory] = useState<SurvHistory | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [historyQuery, setHistoryQuery] = useState("");
  const [historyPage, setHistoryPage] = useState(1);
  const [height, setHeight] = useState<number>(900);

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
        const json = await getJson<SurvSummary>("/api/surveillance/summary");
        if (!stopped) {
          setSummary(json);
          setError("");
        }
      } catch (e: any) {
        if (!stopped) setError(e?.message || "Failed to load surveillance summary.");
      }
    };
    tick();
    const id = window.setInterval(tick, 5000);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
  }, []);

  useEffect(() => {
    let stopped = false;
    const load = async () => {
      try {
        const q = historyQuery.trim();
        const json = await getJson<SurvHistory>(
          `/api/surveillance/history?q=${encodeURIComponent(q)}&page=${historyPage}&limit=50`
        );
        if (!stopped) setHistory(json);
      } catch {
        // ignore
      }
    };
    if (tab === "history") load();
    return () => {
      stopped = true;
    };
  }, [tab, historyQuery, historyPage]);

  const rows = useMemo(() => {
    const raw = tab === "level2" ? summary?.rows?.level2 : summary?.rows?.under;
    const all = (raw || []) as SurvRow[];
    const q = search.trim().toLowerCase();
    if (!q) return all;
    return all.filter((r) =>
      [r.pppoe, r.ip].filter(Boolean).some((x) => String(x).toLowerCase().includes(q))
    );
  }, [summary, tab, search]);

  const counts = summary?.counts || {};
  const stableWindow = summary?.stable_window_days;

  const removeRow = async (pppoe: string) => {
    if (!pppoe) return;
    const ok = window.confirm(`Remove ${pppoe} from surveillance?`);
    if (!ok) return;
    await postForm("/surveillance/remove", { pppoe, tab: tab === "level2" ? "level2" : "under" });
    const json = await getJson<SurvSummary>("/api/surveillance/summary");
    setSummary(json);
  };

  const fixRow = async (pppoe: string) => {
    if (!pppoe) return;
    const reason = (window.prompt("Reason for Account Fixed:") || "").trim();
    if (!reason) return;
    await postForm("/surveillance/fixed", { pppoe, reason });
    const json = await getJson<SurvSummary>("/api/surveillance/summary");
    setSummary(json);
  };

  return (
    <div className="space-y-6">
      <Panel
        title="Under Surveillance"
        right={
          <span className="text-slate-400">
            Updated: {summary?.updated_at || "n/a"}
            {stableWindow ? ` · Stability window: ${Number(stableWindow).toFixed(3)} days` : ""}
          </span>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              tab === "under"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setTab("under")}
          >
            Under ({Number(counts.under_total || 0)})
          </button>
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              tab === "level2"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setTab("level2")}
          >
            Level II ({Number(counts.level2_total || 0)})
          </button>
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              tab === "history"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setTab("history")}
          >
            History
          </button>
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              tab === "settings"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setTab("settings")}
          >
            Settings
          </button>

          {tab === "under" ? (
            <div className="ml-2 flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className="rounded-md border border-white/10 bg-white/5 px-2 py-1">
                Auto: {Number(counts.under_auto || 0)}
              </span>
              <span className="rounded-md border border-white/10 bg-white/5 px-2 py-1">
                Manual: {Number(counts.under_manual || 0)}
              </span>
            </div>
          ) : null}

          <div className="ml-auto w-full sm:w-72">
            {tab === "history" ? (
              <input
                className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
                placeholder="Search history"
                value={historyQuery}
                onChange={(e) => {
                  setHistoryPage(1);
                  setHistoryQuery(e.target.value);
                }}
              />
            ) : tab === "settings" ? null : (
              <input
                className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
                placeholder="Search PPPoE / IP"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            )}
          </div>
        </div>

        {error ? <div className="mt-3 text-sm text-red-300">{error}</div> : null}

        {tab === "settings" ? (
          <div className="mt-4 rounded-lg border border-white/10 overflow-hidden bg-black/20">
            <iframe
              title="Surveillance Settings"
              src="/surveillance?tab=settings&embed=1"
              style={{ width: "100%", height }}
              className="block w-full"
            />
          </div>
        ) : tab === "history" ? (
          <div className="mt-4 overflow-auto rounded-lg border border-white/10">
            <table className="min-w-[1000px] w-full text-sm">
              <thead className="bg-slate-950/60">
                <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                  <th className="px-3 py-2">PPPoE</th>
                  <th className="px-3 py-2">Last IP</th>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">State</th>
                  <th className="px-3 py-2">Observed</th>
                  <th className="px-3 py-2">Started</th>
                  <th className="px-3 py-2">Ended</th>
                  <th className="px-3 py-2">Reason</th>
                </tr>
              </thead>
              <tbody>
                {(history?.rows || []).length ? (
                  (history?.rows || []).map((r, idx) => (
                    <tr key={`${r.id || idx}`} className="border-t border-white/5">
                      <td className="px-3 py-2 font-semibold">{String(r.pppoe || "")}</td>
                      <td className="px-3 py-2 text-slate-300">{String(r.last_ip || "—")}</td>
                      <td className="px-3 py-2 text-slate-300">{String(r.source || "—")}</td>
                      <td className="px-3 py-2 text-slate-300">
                        {r.currently_active ? (
                          <span className="rounded-md border border-green-400/20 bg-green-500/10 px-2 py-1 text-xs text-green-200">
                            Active
                          </span>
                        ) : (
                          <span className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-300">
                            Inactive
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-slate-300">{Number(r.observed_count || 0)}</td>
                      <td className="px-3 py-2 text-slate-400">{String(r.started_at_ph || "—")}</td>
                      <td className="px-3 py-2 text-slate-400">{String(r.ended_at_ph || "—")}</td>
                      <td className="px-3 py-2 text-slate-400">{String(r.end_reason || "—")}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-3 text-slate-400" colSpan={8}>
                      Loading…
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            <div className="flex items-center justify-between px-3 py-3 text-xs text-slate-400 border-t border-white/5">
              <div>
                Page {Number(history?.page || 1)} / {Number(history?.pages || 1)} · Total {Number(history?.total || 0)}
              </div>
              <div className="flex gap-2">
                <button
                  className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-200 hover:bg-white/10 disabled:opacity-50"
                  disabled={Number(history?.page || 1) <= 1}
                  onClick={() => setHistoryPage((p) => Math.max(p - 1, 1))}
                >
                  Prev
                </button>
                <button
                  className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-200 hover:bg-white/10 disabled:opacity-50"
                  disabled={Number(history?.page || 1) >= Number(history?.pages || 1)}
                  onClick={() => setHistoryPage((p) => p + 1)}
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="mt-4 overflow-auto rounded-lg border border-white/10">
            <table className="min-w-[1200px] w-full text-sm">
              <thead className="bg-slate-950/60">
                <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                  <th className="px-3 py-2">PPPoE</th>
                  <th className="px-3 py-2">IPv4</th>
                  <th className="px-3 py-2">Ping</th>
                  <th className="px-3 py-2">Loss</th>
                  <th className="px-3 py-2">Latency</th>
                  <th className="px-3 py-2">Added By</th>
                  <th className="px-3 py-2">Under For</th>
                  <th className="px-3 py-2">Down For</th>
                  <th className="px-3 py-2">Last Ping</th>
                  <th className="px-3 py-2">Optical RX</th>
                  <th className="px-3 py-2">Optical Last</th>
                  <th className="px-3 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.length ? (
                  rows.map((r, idx) => (
                    <tr key={`${r.pppoe}-${idx}`} className="border-t border-white/5">
                      <td className="px-3 py-2 font-semibold">{r.pppoe}</td>
                      <td className="px-3 py-2 text-slate-300">{r.ip || "n/a"}</td>
                      <td className="px-3 py-2">
                        {r.ok ? (
                          <span className="rounded-md border border-green-400/20 bg-green-500/10 px-2 py-1 text-xs text-green-200">
                            Up
                          </span>
                        ) : (
                          <span className="rounded-md border border-red-400/20 bg-red-500/10 px-2 py-1 text-xs text-red-200">
                            Down
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-slate-300">{formatLoss(r.loss)}</td>
                      <td className="px-3 py-2 text-slate-300">{formatMs(r.avg_ms)}</td>
                      <td className="px-3 py-2 text-slate-300">
                        {String(r.added_mode || "manual") === "auto" ? (
                          <span className="rounded-md border border-sky-400/20 bg-sky-500/10 px-2 py-1 text-xs text-sky-200">
                            Auto
                          </span>
                        ) : (
                          <span className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-300">
                            Manual
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-slate-400">{underForFromIso(r.added_at_iso)}</td>
                      <td className="px-3 py-2 text-slate-400">{r.down_for || "—"}</td>
                      <td className="px-3 py-2 text-slate-400">{r.last_check || "n/a"}</td>
                      <td className="px-3 py-2 text-slate-300">{formatRx(r.optical_rx)}</td>
                      <td className="px-3 py-2 text-slate-400">{r.optical_last || "n/a"}</td>
                      <td className="px-3 py-2 text-right">
                        {tab === "level2" ? (
                          <button
                            className="rounded-lg border border-green-400/20 bg-green-500/10 px-2 py-1 text-xs text-green-200 hover:bg-green-500/20"
                            onClick={() => fixRow(r.pppoe)}
                            title="Account Fixed"
                          >
                            Fixed
                          </button>
                        ) : null}
                        <button
                          className="ml-2 rounded-lg border border-red-400/20 bg-red-500/10 px-2 py-1 text-xs text-red-200 hover:bg-red-500/20"
                          onClick={() => removeRow(r.pppoe)}
                          title="Remove"
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-3 text-slate-400" colSpan={12}>
                      {summary ? "No rows." : "Loading…"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

