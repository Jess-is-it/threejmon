import { Panel } from "../ui/Panel";

export function DashboardPage() {
  return (
    <div className="space-y-6">
      <Panel title="Welcome">
        <div className="text-sm text-slate-300">
          This is the new React/Vite UI. We’ll migrate features page-by-page while keeping the legacy UI working.
        </div>
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Usage">
          <div className="text-sm text-slate-300">Live PPPoE usage monitoring + history + rules.</div>
          <a className="mt-3 inline-flex text-sm text-sky-300 hover:underline" href="/app/usage">
            Open Usage →
          </a>
        </Panel>
        <Panel title="Offline">
          <div className="text-sm text-slate-300">Offline detection via MikroTik vs secrets or MikroTik vs Radius.</div>
          <a className="mt-3 inline-flex text-sm text-sky-300 hover:underline" href="/app/offline">
            Open Offline →
          </a>
        </Panel>
      </div>
    </div>
  );
}

