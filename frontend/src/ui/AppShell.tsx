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

function SideLink(props: { to: string; label: string }) {
  return (
    <NavLink
      to={props.to}
      className={({ isActive }) =>
        [
          "block rounded-lg px-3 py-2 text-sm font-medium",
          isActive ? "bg-white/10 text-white" : "text-slate-200 hover:bg-white/5 hover:text-white",
        ].join(" ")
      }
      end
    >
      {props.label}
    </NavLink>
  );
}

export function AppShell() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sys, setSys] = useState<SysResources>({});

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
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="lg:flex">
        <aside
          className={[
            "fixed inset-y-0 left-0 z-50 w-72 border-r border-white/10 bg-slate-950/60 backdrop-blur lg:static lg:block",
            sidebarOpen ? "block" : "hidden",
          ].join(" ")}
        >
          <div className="flex items-center justify-between gap-2 px-4 py-4">
            <a href="/app" className="text-sm font-semibold tracking-wide text-white no-underline">
              ThreeJ Notifier
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
          <nav className="px-3 pb-6 space-y-1">
            <SideLink to="/app" label="Dashboard" />
            <SideLink to="/app/surveillance" label="Under Surveillance" />
            <SideLink to="/app/profile-review" label="Profile Review" />
            <div className="pt-4 text-xs font-semibold tracking-wide text-slate-400 px-3">Monitoring</div>
            <SideLink to="/app/usage" label="Usage" />
            <SideLink to="/app/offline" label="Offline" />
            <SideLink to="/app/optical" label="Optical" />
            <SideLink to="/app/accounts-ping" label="Accounts Ping" />
            <SideLink to="/app/wan" label="WAN Ping" />
            <SideLink to="/app/pulsewatch" label="ISP Pulsewatch" />
            <SideLink to="/app/system" label="System Settings" />
          </nav>
        </aside>

        <div className="flex-1">
          <header className="sticky top-0 z-40 border-b border-white/10 bg-slate-950/60 backdrop-blur">
            <div className="flex items-center gap-3 px-4 py-3">
              <button
                type="button"
                className="inline-flex items-center justify-center rounded-lg border border-white/10 bg-white/5 px-2 py-2 text-slate-200 hover:bg-white/10 lg:hidden"
                onClick={() => setSidebarOpen(true)}
                aria-label="Open sidebar"
              >
                ☰
              </button>
              <div className="text-sm font-semibold">Unified ISP Ops</div>
              <div className="ml-auto hidden items-center gap-4 lg:flex">
                {metrics.map((m) => (
                  <div key={m.label} className="text-xs text-slate-300">
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

