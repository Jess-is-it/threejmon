import { PropsWithChildren } from "react";

export function Panel(props: PropsWithChildren<{ title: string; right?: React.ReactNode }>) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/5">
      <div className="flex items-center justify-between gap-2 border-b border-white/10 px-4 py-3">
        <div className="text-sm font-semibold">{props.title}</div>
        {props.right ? <div className="text-xs text-slate-300">{props.right}</div> : null}
      </div>
      <div className="p-4">{props.children}</div>
    </div>
  );
}

