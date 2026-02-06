import { useEffect, useMemo, useState } from "react";
import { getJson } from "../api/http";
import { Panel } from "../ui/Panel";

type UsageSummary = {
  updated_at?: string;
  counts?: { issues?: number; stable?: number; offline?: number };
  rows?: { issues?: any[]; stable?: any[]; offline?: any[] };
};

function formatBps(bps: number | null | undefined) {
  const v = Number(bps || 0);
  if (!Number.isFinite(v) || v <= 0) return "—";
  const kb = v / 1000;
  const mb = kb / 1000;
  if (mb >= 1) return `${mb.toFixed(2)} Mbps`;
  return `${kb.toFixed(0)} Kbps`;
}

function formatBytes(bytes: number | null | undefined) {
  const v = Number(bytes || 0);
  if (!Number.isFinite(v) || v <= 0) return "—";
  const kb = v / 1024;
  const mb = kb / 1024;
  const gb = mb / 1024;
  if (gb >= 1) return `${gb.toFixed(2)} GB`;
  if (mb >= 1) return `${mb.toFixed(1)} MB`;
  return `${kb.toFixed(0)} KB`;
}

export function UsagePage() {
  const [view, setView] = useState<"status" | "settings">("status");
  const [activeTab, setActiveTab] = useState<"issues" | "stable">("stable");
  const [data, setData] = useState<UsageSummary | null>(null);
  const [error, setError] = useState<string>("");
  const [search, setSearch] = useState("");
  const [height, setHeight] = useState<number>(900);

  useEffect(() => {
    let stopped = false;
    const tick = async () => {
      try {
        const json = await getJson<UsageSummary>("/usage/summary");
        if (!stopped) {
          setData(json);
          setError("");
        }
      } catch (e: any) {
        if (!stopped) setError(e?.message || "Failed to load usage summary.");
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
    const onResize = () => {
      const h = Math.max(window.innerHeight - 220, 560);
      setHeight(h);
    };
    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const rows = useMemo(() => {
    const all = (data?.rows?.[activeTab] || []) as any[];
    const q = search.trim().toLowerCase();
    if (!q) return all;
    return all.filter((r) =>
      [r?.pppoe, r?.router_name, r?.router_id, r?.profile]
        .filter(Boolean)
        .map((x) => String(x).toLowerCase())
        .some((x) => x.includes(q))
    );
  }, [data, activeTab, search]);

  const counts = data?.counts || {};

  return (
    <div className="space-y-6">
      <Panel
        title="Usage"
        right={<span className="text-slate-400">Updated: {data?.updated_at ? String(data.updated_at) : "n/a"}</span>}
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
            <iframe title="Usage Settings" src="/settings/usage?embed=1" style={{ width: "100%", height }} className="block w-full" />
          </div>
        ) : (
          <>
        <div className="flex flex-wrap items-center gap-2">
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              activeTab === "stable"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setActiveTab("stable")}
          >
            Stable ({Number(counts.stable || 0)})
          </button>
          <button
            className={[
              "rounded-lg px-3 py-2 text-sm font-medium border",
              activeTab === "issues"
                ? "border-white/10 bg-white/10 text-white"
                : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10",
            ].join(" ")}
            onClick={() => setActiveTab("issues")}
          >
            Issues ({Number(counts.issues || 0)})
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
          <table className="min-w-[960px] w-full text-sm">
            <thead className="bg-slate-950/60">
              <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                <th className="px-3 py-2">PPPoE</th>
                <th className="px-3 py-2">Router</th>
                <th className="px-3 py-2">DL Rate</th>
                <th className="px-3 py-2">UL Rate</th>
                <th className="px-3 py-2">DL Total</th>
                <th className="px-3 py-2">UL Total</th>
                <th className="px-3 py-2">Profile</th>
              </tr>
            </thead>
            <tbody>
              {rows.length ? (
                rows.map((r, idx) => (
                  <tr key={`${r?.router_id || ""}-${r?.pppoe || ""}-${idx}`} className="border-t border-white/5">
                    <td className="px-3 py-2 font-semibold">{String(r?.pppoe || "")}</td>
                    <td className="px-3 py-2 text-slate-300">{String(r?.router_name || r?.router_id || "")}</td>
                    <td className="px-3 py-2 text-slate-300">{formatBps(r?.tx_bps)}</td>
                    <td className="px-3 py-2 text-slate-300">{formatBps(r?.rx_bps)}</td>
                    <td className="px-3 py-2 text-slate-300">{formatBytes(r?.bytes_out)}</td>
                    <td className="px-3 py-2 text-slate-300">{formatBytes(r?.bytes_in)}</td>
                    <td className="px-3 py-2 text-slate-400">{String(r?.profile || "—")}</td>
                  </tr>
                ))
              ) : (
                <tr className="border-t border-white/5">
                  <td className="px-3 py-3 text-slate-400" colSpan={7}>
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
