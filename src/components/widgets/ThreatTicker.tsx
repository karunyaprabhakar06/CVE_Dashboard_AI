import { useMemo } from "react";
import { useStore } from "@/lib/store";
import { SEVERITY_COLORS } from "@/lib/utils";

export default function ThreatTicker() {
  const feed = useStore((s) => s.feed);

  const items = useMemo(() => {
    if (feed.length === 0)
      return [
        {
          id: "boot",
          severity: "MEDIUM" as const,
          title: "Initializing live threat feed…",
          source: "SYSTEM",
          ts: new Date().toISOString(),
        },
      ];
    return feed;
  }, [feed]);

  // duplicate for seamless loop
  const loop = [...items, ...items];

  return (
    <div className="glass overflow-hidden border-y border-cyber-cyan/10 relative">
      <div className="ticker-fade ticker-fade-l absolute left-0 top-0 h-full w-32 z-10 pointer-events-none" />
      <div className="ticker-fade ticker-fade-r absolute right-0 top-0 h-full w-32 z-10 pointer-events-none" />
      <div className="flex items-center gap-2 px-4 py-2.5">
        <span className="chip border-cyber-red/30 text-cyber-red bg-cyber-red/10 font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-cyber-red animate-pulse" />
          LIVE FEED
        </span>
        <div className="flex-1 overflow-hidden">
          <div className="flex gap-10 whitespace-nowrap animate-ticker">
            {loop.map((it, i) => (
              <div key={`${it.id}-${i}`} className="flex items-center gap-2 text-xs font-mono">
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: SEVERITY_COLORS[it.severity] }}
                />
                <span className="text-slate-500">[{it.source}]</span>
                <span
                  className="font-semibold"
                  style={{ color: SEVERITY_COLORS[it.severity] }}
                >
                  {it.severity}
                </span>
                <span className="text-slate-300 max-w-[640px] truncate">
                  {it.title}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
