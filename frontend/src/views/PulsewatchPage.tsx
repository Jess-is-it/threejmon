import { useEffect, useMemo, useState } from "react";
import { getJson } from "../api/http";
import { Panel } from "../ui/Panel";

type Speedtest = {
  download_mbps?: number | null;
  upload_mbps?: number | null;
  latency_ms?: number | null;
  timestamp?: string;
};

type PulseRow = {
  row_id?: string;
  label?: string;
  core_label?: string;
  list_name?: string;
  source_ip?: string;
  last_check?: string;
  loss_max?: number | null;
  avg_max?: number | null;
  down_samples?: number;
  total_samples?: number;
  loss_points?: string;
  avg_points?: string;
  speed?: Speedtest;
};

type PulseSummary = {
  total?: number;
  last_check?: string;
  rows?: PulseRow[];
};

type SeriesPoint = { ts?: string; value?: number | null };

function formatPct(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(1)}%`;
}

function formatMs(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(0)} ms`;
}

function formatMbps(v: number | null | undefined) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return "—";
  if (n >= 100) return `${n.toFixed(0)} Mbps`;
  if (n >= 10) return `${n.toFixed(1)} Mbps`;
  return `${n.toFixed(2)} Mbps`;
}

function Sparkline(props: { points?: string; width: number; height: number; color?: string }) {
  const pts = (props.points || "").trim();
  return (
    <svg viewBox={`0 0 ${props.width} ${props.height}`} width={props.width} height={props.height} className="block">
      <polyline
        points={pts}
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        className={props.color || "text-sky-300"}
      />
    </svg>
  );
}

function seriesToPolyline(values: number[], width: number, height: number, minVal: number, maxVal: number) {
  if (!values.length) return "";
  const span = Math.max(maxVal - minVal, 1);
  const step = width / Math.max(values.length - 1, 1);
  const pts: string[] = [];
  for (let i = 0; i < values.length; i++) {
    const x = i * step;
    const v = Math.max(minVal, Math.min(maxVal, values[i]));
    const y = height - ((v - minVal) / span) * height;
    pts.push(`${x.toFixed(1)},${y.toFixed(1)}`);
  }
  return pts.join(" ");
}

export function PulsewatchPage() {
  const [view, setView] = useState<"status" | "settings">("status");
  const [lossMinutes, setLossMinutes] = useState<number>(120);
  const [data, setData] = useState<PulseSummary | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [height, setHeight] = useState<number>(900);

  const [modal, setModal] = useState<{ row?: PulseRow; series?: SeriesPoint[]; loading?: boolean; error?: string } | null>(
    null
  );

  const url = useMemo(() => `/pulsewatch/summary?target=all&loss_minutes=${encodeURIComponent(String(lossMinutes))}`, [lossMinutes]);

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
        const json = await getJson<PulseSummary>(url);
        if (stopped) return;
        setData(json);
        setError("");
      } catch (e: any) {
        if (stopped) return;
        setError(e?.message || "Failed to load pulsewatch summary.");
      }
    };
    tick();
    const id = window.setInterval(tick, 5000);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
  }, [url]);

  const rows = useMemo(() => {
    const all = (data?.rows || []) as PulseRow[];
    const q = search.trim().toLowerCase();
    if (!q) return all;
    return all.filter((r) =>
      [r.label, r.core_label, r.list_name, r.source_ip].filter(Boolean).some((x) => String(x).toLowerCase().includes(q))
    );
  }, [data, search]);

  const openLossModal = async (row: PulseRow) => {
    const rowId = (row.row_id || "").trim();
    if (!rowId) return;
    setModal({ row, series: [], loading: true, error: "" });
    try {
      const json = await getJson<{ series?: SeriesPoint[] }>(
        `/pulsewatch/loss_series?row_id=${encodeURIComponent(rowId)}&target=all&loss_minutes=${encodeURIComponent(String(lossMinutes))}`
      );
      setModal({ row, series: json.series || [], loading: false, error: "" });
    } catch (e: any) {
      setModal({ row, series: [], loading: false, error: e?.message || "Failed to load loss series." });
    }
  };

  return (
    <div className="space-y-6">
      <Panel
        title="ISP Pulsewatch"
        subtitle="Live latency/loss view per ISP source IP."
        right={<span className="text-slate-400">Last check: {data?.last_check || "n/a"}</span>}
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
            <iframe title="Pulsewatch Settings" src="/settings/pulsewatch?embed=1" style={{ width: "100%", height }} className="block w-full" />
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <select
                className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
                value={String(lossMinutes)}
                onChange={(e) => setLossMinutes(Number(e.target.value || 120))}
              >
                {[30, 60, 120, 240, 480].map((m) => (
                  <option key={m} value={String(m)}>
                    Loss window: {m}m
                  </option>
                ))}
              </select>
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
              <table className="min-w-[1180px] w-full text-sm">
                <thead className="bg-slate-950/60">
                  <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                    <th className="px-3 py-2">ISP</th>
                    <th className="px-3 py-2">Source IP</th>
                    <th className="px-3 py-2">Last Check</th>
                    <th className="px-3 py-2">Loss Max</th>
                    <th className="px-3 py-2">Latency Max</th>
                    <th className="px-3 py-2">Down</th>
                    <th className="px-3 py-2">Loss Trend</th>
                    <th className="px-3 py-2">Latency Trend</th>
                    <th className="px-3 py-2">Speedtest</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.length ? (
                    rows.map((r, idx) => (
                      <tr key={`${r.row_id || ""}-${idx}`} className="border-t border-white/5">
                        <td className="px-3 py-2 font-semibold text-white">{r.label || "—"}</td>
                        <td className="px-3 py-2 text-slate-300">{r.source_ip || "—"}</td>
                        <td className="px-3 py-2 text-slate-300">{r.last_check || "—"}</td>
                        <td className="px-3 py-2 text-slate-300">{formatPct(r.loss_max)}</td>
                        <td className="px-3 py-2 text-slate-300">{formatMs(r.avg_max)}</td>
                        <td className="px-3 py-2 text-slate-300">
                          {Number(r.down_samples || 0)} / {Number(r.total_samples || 0)}
                        </td>
                        <td className="px-3 py-2">
                          <button
                            className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-slate-200 hover:bg-white/10"
                            onClick={() => openLossModal(r)}
                            title="Open loss chart"
                          >
                            <Sparkline points={r.loss_points} width={120} height={30} color="text-rose-300" />
                          </button>
                        </td>
                        <td className="px-3 py-2">
                          <Sparkline points={r.avg_points} width={120} height={30} color="text-sky-300" />
                        </td>
                        <td className="px-3 py-2 text-slate-300">
                          <div className="text-xs">
                            DL: <span className="text-slate-200">{formatMbps(r.speed?.download_mbps)}</span>
                          </div>
                          <div className="text-xs">
                            UL: <span className="text-slate-200">{formatMbps(r.speed?.upload_mbps)}</span>
                          </div>
                          <div className="text-xs">
                            Ping: <span className="text-slate-200">{formatMs(r.speed?.latency_ms)}</span>
                          </div>
                        </td>
                      </tr>
                    ))
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
          </>
        )}
      </Panel>

      {modal ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          role="dialog"
          aria-modal="true"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setModal(null);
          }}
        >
          <div className="w-full max-w-4xl rounded-2xl border border-white/10 bg-slate-950 shadow-xl">
            <div className="flex items-start justify-between gap-3 border-b border-white/10 p-4">
              <div>
                <div className="text-lg font-semibold text-white">{modal.row?.label || "Loss"}</div>
                <div className="text-sm text-slate-400">
                  {modal.row?.source_ip ? `Source IP: ${modal.row.source_ip}` : ""}
                  {modal.row?.last_check ? ` · Last check: ${modal.row.last_check}` : ""}
                </div>
              </div>
              <button
                className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10"
                onClick={() => setModal(null)}
              >
                Close
              </button>
            </div>
            <div className="p-4">
              {modal.loading ? <div className="text-sm text-slate-300">Loading…</div> : null}
              {modal.error ? <div className="text-sm text-red-300">{modal.error}</div> : null}
              {!modal.loading && !modal.error ? (
                <div className="rounded-xl border border-white/10 bg-black/20 p-3 text-slate-200">
                  {(() => {
                    const vals = (modal.series || [])
                      .map((p) => Number(p.value))
                      .filter((n) => Number.isFinite(n)) as number[];
                    const pts = seriesToPolyline(vals, 640, 200, 0, 100);
                    return <Sparkline points={pts} width={640} height={200} color="text-rose-300" />;
                  })()}
                  <div className="mt-2 text-xs text-slate-400">Loss % over the selected window.</div>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

