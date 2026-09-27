import { cn, SEVERITY_BG } from "@/lib/utils";
import type { Severity } from "@/lib/types";

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span className={cn("chip", SEVERITY_BG[severity], className)}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

export function ScoreBar({
  value,
  max = 10,
  color = "#00D9FF",
  label,
}: {
  value: number;
  max?: number;
  color?: string;
  label?: string;
}) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="flex items-center gap-2 w-full">
      <div className="relative flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 rounded-full"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, ${color}40, ${color})`,
            boxShadow: `0 0 12px ${color}80`,
          }}
        />
        <div className="absolute inset-0 shimmer opacity-50" />
      </div>
      <span className="text-[11px] font-mono text-slate-300 tabular-nums w-10 text-right">
        {label ?? value.toFixed(1)}
      </span>
    </div>
  );
}
