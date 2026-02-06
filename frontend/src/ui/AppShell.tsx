import { NavLink, Outlet } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import { getJson } from "../api/http";

type SysResources = {
  cpu_pct?: number;
  ram_pct?: number;
  disk_pct?: number;
  uptime_seconds?: number;
};

function formatUptime(seconds?: number) {
  const s = Math.max(Number(seconds || 0), 0);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function SideLink(props: { to: string; label: string; compact?: boolean }) {
  return (
    <NavLink
      to={props.to}
      className={({ isActive }) =>
        [
          "flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium transition-colors",
          props.compact ? "justify-center" : "",
          isActive
            ? "bg-white/10 text-white shadow-[0_0_0_1px_rgba(255,255,255,0.06)]"
            : "text-slate-200 hover:bg-white/5 hover:text-white",
        ].join(" ")
      }
      end
      title={props.compact ? props.label : undefined}
    >
      <span className="h-2 w-2 rounded-full bg-slate-500/60" aria-hidden="true" />
      {props.compact ? null : <span>{props.label}</span>}
    </NavLink>
  );
}

export function AppShell() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sys, setSys] = useState<SysResources>({});
  const [collapsed, setCollapsed] = useState(false);

  const metrics = useMemo(() => {
    return [
      { label: "CPU", value: `${Math.round(Number(sys.cpu_pct || 0))}%` },
      { label: "RAM", value: `${Math.round(Number(sys.ram_pct || 0))}%` },
      { label: "DISK", value: `${Math.round(Number(sys.disk_pct || 0))}%` },
      { label: "UPTIME", value: formatUptime(sys.uptime_seconds) },
    ];
  }, [sys]);

  useEffect(() => {
    let stopped = false;
    const tick = async () => {
      try {
        const data = await getJson<SysResources>("/system/resources");
        if (!stopped) setSys(data || {});
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-950 to-slate-900 text-slate-100">
      <div className="lg:flex">
        <aside
          className={[
            "fixed inset-y-0 left-0 z-50 border-r border-white/10 bg-slate-950/60 backdrop-blur lg:static lg:block",
            collapsed ? "w-20" : "w-72",
            sidebarOpen ? "block" : "hidden",
          ].join(" ")}
        >
          <div className="flex items-center justify-between gap-2 px-4 py-4">
            <a
              href="/app"
              className="flex items-center gap-2 text-sm font-semibold tracking-wide text-white no-underline"
            >
              <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-sky-500/20 text-sky-200 shadow-[0_0_0_1px_rgba(14,165,233,0.25)]">
                3J
              </span>
              {collapsed ? null : <span>ThreeJ Notifier</span>}
            </a>
            <button
              type="button"
              className="inline-flex items-center justify-center rounded-lg border border-white/10 bg-white/5 px-2 py-2 text-slate-200 hover:bg-white/10 lg:hidden"
              onClick={() => setSidebarOpen(false)}
              aria-label="Close sidebar"
            >
              ✕
            </button>
          </div>
          <div className="px-3 pb-2">
            <button
              type="button"
              className="hidden w-full items-center justify-center rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-white/10 lg:flex"
              onClick={() => setCollapsed((v) => !v)}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? "→" : "←"}
            </button>
          </div>
          <nav className={["px-3 pb-6 space-y-1", collapsed ? "px-2" : ""].join(" ")}>
            <SideLink to="/app" label="Dashboard" compact={collapsed} />
            <SideLink to="/app/surveillance" label="Under Surveillance" compact={collapsed} />
            <SideLink to="/app/profile-review" label="Profile Review" compact={collapsed} />
            {collapsed ? (
              <div className="pt-4" />
            ) : (
              <div className="pt-4 text-xs font-semibold tracking-wide text-slate-400 px-3">Monitoring</div>
            )}
            <SideLink to="/app/usage" label="Usage" compact={collapsed} />
            <SideLink to="/app/offline" label="Offline" compact={collapsed} />
            <SideLink to="/app/optical" label="Optical" compact={collapsed} />
            <SideLink to="/app/accounts-ping" label="Accounts Ping" compact={collapsed} />
            <SideLink to="/app/wan" label="WAN Ping" compact={collapsed} />
            <SideLink to="/app/pulsewatch" label="ISP Pulsewatch" compact={collapsed} />
            <SideLink to="/app/system" label="System Settings" compact={collapsed} />
          </nav>
        </aside>

        <div className="flex-1">
          <header className="sticky top-0 z-40 border-b border-white/10 bg-slate-950/60 backdrop-blur">
            <div className="flex flex-wrap items-center gap-3 px-4 py-3">
              <button
                type="button"
                className="inline-flex items-center justify-center rounded-lg border border-white/10 bg-white/5 px-2 py-2 text-slate-200 hover:bg-white/10 lg:hidden"
                onClick={() => setSidebarOpen(true)}
                aria-label="Open sidebar"
              >
                ☰
              </button>
              <div className="flex items-center gap-2">
                <div className="text-sm font-semibold tracking-tight">Unified ISP Ops</div>
                <span className="hidden rounded-full border border-white/10 bg-white/5 px-2 py-1 text-[11px] font-medium text-slate-300 sm:inline-flex">
                  TailwindAdmin migration
                </span>
              </div>
              <div className="ml-auto hidden items-center gap-2 lg:flex">
                {metrics.map((m) => (
                  <div
                    key={m.label}
                    className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-200"
                  >
                    <span className="text-slate-400">{m.label}</span> {m.value}
                  </div>
                ))}
              </div>
            </div>
          </header>
          <main className="px-4 py-6">
            <Outlet />
            <div className="mt-10 text-xs text-slate-500">
              Legacy UI is still available while we migrate pages:{" "}
              <a className="text-sky-300 hover:underline" href="/">
                Open legacy dashboard
              </a>
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}
