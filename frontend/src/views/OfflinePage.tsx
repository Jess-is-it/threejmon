import { useEffect, useMemo, useState } from "react";
import { getJson } from "../api/http";
import { Panel } from "../ui/Panel";

type OfflineSummary = {
  updated_at?: string;
  mode?: string;
  last_check?: string;
  rows?: any[];
  counts?: { offline?: number };
};

type OfflineHistory = {
  count?: number;
  rows?: any[];
};

export function OfflinePage() {
  const [view, setView] = useState<"status" | "settings">("status");
  const [tab, setTab] = useState<"offline" | "history">("offline");
  const [summary, setSummary] = useState<OfflineSummary | null>(null);
  const [history, setHistory] = useState<OfflineHistory | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [height, setHeight] = useState<number>(900);

  useEffect(() => {
    let stopped = false;
    const tick = async () => {
      try {
        const s = await getJson<OfflineSummary>("/offline/summary");
        if (!stopped) setSummary(s);
      } catch (e: any) {
        if (!stopped) setError(e?.message || "Failed to load offline summary.");
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
    const tick = async () => {
      try {
        const h = await getJson<OfflineHistory>("/offline/history?days=30&limit=500");
        if (!stopped) setHistory(h);
      } catch {
        // ignore
      }
    };
    tick();
    const id = window.setInterval(tick, 15000);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
  }, []);

  useEffect(() => {
    const onResize = () => {
      const h = Math.max(window.innerHeight - 220, 560);
      setHeight(h);
    };
    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const rows = useMemo(() => {
    const all = (tab === "offline" ? summary?.rows : history?.rows) || [];
    const q = search.trim().toLowerCase();
    if (!q) return all as any[];
    return (all as any[]).filter((r) =>
      Object.values(r || {})
        .map((x) => String(x ?? "").toLowerCase())
        .some((x) => x.includes(q))
    );
  }, [tab, summary, history, search]);

  return (
    <div className="space-y-6">
      <Panel
        title="Offline"
        right={
          <span className="text-slate-400">
            Mode: {summary?.mode || "n/a"} · Last poll: {summary?.last_check || "n/a"}
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
          <div className="ml-auto text-xs text-slate-500">
            Settings are rendered from the legacy page for now (embedded).
          </div>
        </div>

        {view === "settings" ? (
          <div className="rounded-lg border border-white/10 overflow-hidden bg-black/20">
            <iframe title="Offline Settings" src="/settings/offline?embed=1" style={{ width: "100%", height }} className="block w-full" />
          </div>
        ) : (
          <>
        <div className="flex flex-wrap items-center gap-2">
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              tab === "offline"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setTab("offline")}
          >
            Offline ({Number(summary?.counts?.offline || 0)})
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
            History ({Number(history?.count || 0)})
          </button>
          <div className="ml-auto w-full sm:w-72">
            <input
              className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
              placeholder="Search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
        {error ? <div className="mt-3 text-sm text-red-300">{error}</div> : null}
        <div className="mt-4 overflow-auto rounded-lg border border-white/10">
          <table className="min-w-[900px] w-full text-sm">
            <thead className="bg-slate-950/60">
              <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                <th className="px-3 py-2">PPPoE</th>
                <th className="px-3 py-2">Router</th>
                {tab === "offline" ? (
                  <>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Profile</th>
                    <th className="px-3 py-2">Offline Since</th>
                  </>
                ) : (
                  <>
                    <th className="px-3 py-2">Start</th>
                    <th className="px-3 py-2">End</th>
                    <th className="px-3 py-2">Duration</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody>
              {rows.length ? (
                rows.map((r, idx) => (
                  <tr key={`${r?.router_id || ""}-${r?.pppoe || ""}-${idx}`} className="border-t border-white/5">
                    <td className="px-3 py-2 font-semibold">{String(r?.pppoe || "")}</td>
                    <td className="px-3 py-2 text-slate-300">{String(r?.router_name || r?.router_id || "")}</td>
                    {tab === "offline" ? (
                      <>
                        <td className="px-3 py-2 text-slate-300">{String(r?.radius_status || "—")}</td>
                        <td className="px-3 py-2 text-slate-400">{String(r?.profile || "—")}</td>
                        <td className="px-3 py-2 text-slate-400">{String(r?.offline_since || "—")}</td>
                      </>
                    ) : (
                      <>
                        <td className="px-3 py-2 text-slate-400">{String(r?.offline_started || "—")}</td>
                        <td className="px-3 py-2 text-slate-400">{String(r?.offline_ended || "—")}</td>
                        <td className="px-3 py-2 text-slate-300">{String(r?.duration || "—")}</td>
                      </>
                    )}
                  </tr>
                ))
              ) : (
                <tr className="border-t border-white/5">
                  <td className="px-3 py-3 text-slate-400" colSpan={6}>
                    {tab === "offline" ? (summary ? "No rows." : "Loading…") : history ? "No rows." : "Loading…"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="mt-4 text-xs text-slate-500">
          Tip: Offline settings (Mode, Radius SSH, minimum duration) are still configured in the legacy Settings UI for now.
        </div>
          </>
        )}
      </Panel>
    </div>
  );
}
