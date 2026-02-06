import { PropsWithChildren } from "react";

export function Panel(
  props: PropsWithChildren<{ title: string; right?: React.ReactNode; subtitle?: React.ReactNode }>
) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 shadow-[0_0_0_1px_rgba(255,255,255,0.02)]">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/10 px-5 py-4">
        <div className="min-w-[240px]">
          <div className="text-base font-semibold tracking-tight text-white">{props.title}</div>
          {props.subtitle ? <div className="mt-0.5 text-xs text-slate-400">{props.subtitle}</div> : null}
        </div>
        {props.right ? <div className="text-xs text-slate-300">{props.right}</div> : null}
      </div>
      <div className="p-5">{props.children}</div>
    </div>
  );
}
