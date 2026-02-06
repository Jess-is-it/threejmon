import { useEffect, useMemo, useState } from "react";
import { getJson } from "../api/http";
import { Panel } from "../ui/Panel";

type WanRow = {
  id?: string;
  label?: string;
  status?: string;
  target?: string;
  last_check?: string;
  last_rtt_ms?: number | null;
  last_error?: string | null;
};

type WanStatus = { rows?: WanRow[]; updated_at?: string };

function badge(status: string) {
  const s = (status || "").toLowerCase();
  if (s === "up") return "bg-emerald-500/15 text-emerald-200 border-emerald-500/20";
  if (s === "down") return "bg-red-500/15 text-red-200 border-red-500/20";
  return "bg-amber-500/15 text-amber-200 border-amber-500/20";
}

function formatMs(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(0)} ms`;
}

export function WanPage() {
  const [view, setView] = useState<"status" | "settings">("status");
  const [data, setData] = useState<WanStatus | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
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
        const json = await getJson<WanStatus>("/wan/status");
        if (stopped) return;
        setData(json);
        setError("");
      } catch (e: any) {
        if (stopped) return;
        setError(e?.message || "Failed to load WAN status.");
      }
    };
    tick();
    const id = window.setInterval(tick, 5000);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
  }, []);

  const rows = useMemo(() => {
    const all = (data?.rows || []) as WanRow[];
    const q = search.trim().toLowerCase();
    if (!q) return all;
    return all.filter((r) => [r.label, r.status, r.target, r.last_error].filter(Boolean).some((x) => String(x).toLowerCase().includes(q)));
  }, [data, search]);

  return (
    <div className="space-y-6">
      <Panel
        title="WAN Ping"
        subtitle="Live WAN state (from MikroTik Netwatch automation + stored state)."
        right={<span className="text-slate-400">Updated: {data?.updated_at || "n/a"}</span>}
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
            <iframe title="WAN Settings" src="/settings/wan?embed=1" style={{ width: "100%", height }} className="block w-full" />
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <div className="ml-auto w-full sm:w-80">
                <input
                  className="w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
                  placeholder="Search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
            </div>

            {error ? <div className="mt-3 text-sm text-red-300">{error}</div> : null}

            <div className="mt-4 overflow-auto rounded-2xl border border-white/10">
              <table className="min-w-[980px] w-full text-sm">
                <thead className="bg-slate-950/60">
                  <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                    <th className="px-3 py-2">WAN</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Target</th>
                    <th className="px-3 py-2">Last RTT</th>
                    <th className="px-3 py-2">Last Check</th>
                    <th className="px-3 py-2">Last Error</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.length ? (
                    rows.map((r, idx) => (
                      <tr key={`${r.id || ""}-${idx}`} className="border-t border-white/5">
                        <td className="px-3 py-2 font-semibold text-white">{r.label || "—"}</td>
                        <td className="px-3 py-2">
                          <span className={["inline-flex items-center rounded-full border px-2 py-1 text-xs", badge(String(r.status || ""))].join(" ")}>
                            {String(r.status || "unknown").toUpperCase()}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-slate-300">{r.target || "—"}</td>
                        <td className="px-3 py-2 text-slate-300">{formatMs(r.last_rtt_ms)}</td>
                        <td className="px-3 py-2 text-slate-300">{r.last_check || "—"}</td>
                        <td className="px-3 py-2 text-slate-400">{(r.last_error || "").trim() || "—"}</td>
                      </tr>
                    ))
                  ) : (
                    <tr className="border-t border-white/5">
                      <td className="px-3 py-3 text-slate-400" colSpan={6}>
                        {data ? "No rows." : "Loading…"}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}

