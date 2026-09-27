import { useMemo } from "react";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";
import { SeverityBadge } from "../ui/SeverityBadge";
import { timeAgo } from "@/lib/utils";

export default function TimelineEvents() {
  const records = useStore((s) => s.records);
  const items = useMemo(() => records.slice(0, 12), [records]);

  return (
    <Panel
      title="Event Timeline"
      subtitle="Most recent ingestion across feeds"
      accent="cyan"
      delay={0.22}
    >
      <ol className="relative pl-6">
        <span className="absolute left-2 top-1 bottom-1 w-px bg-gradient-to-b from-cyber-cyan/40 via-cyber-purple/30 to-transparent" />
        {items.length === 0 && (
          <li className="text-[11px] text-slate-500 font-mono py-2">
            Awaiting first sync…
          </li>
        )}
        {items.map((r) => (
          <li key={r.id} className="relative mb-3 last:mb-0">
            <span className="absolute -left-[18px] top-1.5 w-3 h-3 rounded-full bg-bg border-2 border-cyber-cyan shadow-glow" />
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-white">{r.id}</span>
              <SeverityBadge severity={r.severity} />
              <span className="text-[10px] text-slate-500 font-mono ml-auto">
                {timeAgo(r.modified)} · {r.source}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">
              {r.description}
            </p>
          </li>
        ))}
      </ol>
    </Panel>
  );
}
