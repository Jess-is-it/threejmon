import { useEffect, useMemo, useState } from "react";
import { Panel } from "../ui/Panel";

function withEmbed(url: string) {
  try {
    const u = new URL(url, window.location.origin);
    u.searchParams.set("embed", "1");
    return u.pathname + u.search + u.hash;
  } catch {
    return url;
  }
}

export function PlaceholderPage(props: { title: string; legacyHref: string }) {
  const [height, setHeight] = useState<number>(900);
  const iframeSrc = useMemo(() => withEmbed(props.legacyHref), [props.legacyHref]);

  useEffect(() => {
    const onResize = () => {
      const h = Math.max(window.innerHeight - 180, 520);
      setHeight(h);
    };
    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  return (
    <Panel
      title={props.title}
      right={
        <a className="text-sky-300 hover:underline" href={props.legacyHref} target="_blank" rel="noreferrer">
          Open in new tab →
        </a>
      }
    >
      <div className="rounded-lg border border-white/10 overflow-hidden bg-black/20">
        <iframe
          title={props.title}
          src={iframeSrc}
          style={{ width: "100%", height }}
          className="block w-full"
        />
      </div>
    </Panel>
  );
}
