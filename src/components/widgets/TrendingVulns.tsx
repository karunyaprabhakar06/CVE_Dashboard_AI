import { useMemo } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";

export default function TrendingVulns() {
  const records = useStore((s) => s.records);

  const data = useMemo(() => {
    const buckets: Record<string, { day: string; total: number; critical: number; high: number }> = {};
    const now = Date.now();
    for (let i = 13; i >= 0; i--) {
      const d = new Date(now - i * 86400000);
      const key = d.toISOString().slice(5, 10);
      buckets[key] = { day: key, total: 0, critical: 0, high: 0 };
    }
    for (const r of records) {
      const key = new Date(r.modified).toISOString().slice(5, 10);
      if (!buckets[key]) continue;
      buckets[key].total++;
      if (r.severity === "CRITICAL") buckets[key].critical++;
      if (r.severity === "HIGH") buckets[key].high++;
    }
    return Object.values(buckets);
  }, [records]);

  return (
    <Panel
      title="Trending Vulnerabilities · 14d"
      subtitle="New & modified CVEs across all sources"
      accent="cyan"
      delay={0.1}
    >
      <div className="h-[240px]">
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 10, right: 12, left: -12, bottom: 0 }}>
            <defs>
              <linearGradient id="gTotal" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#00D9FF" stopOpacity={0.6} />
                <stop offset="100%" stopColor="#00D9FF" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gCrit" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#EF4444" stopOpacity={0.6} />
                <stop offset="100%" stopColor="#EF4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gHigh" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#F59E0B" stopOpacity={0.5} />
                <stop offset="100%" stopColor="#F59E0B" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1F2A40" strokeDasharray="3 6" vertical={false} />
            <XAxis dataKey="day" stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
            <YAxis stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
            <Tooltip
              contentStyle={{
                background: "#0B1020",
                border: "1px solid #1F2A40",
                borderRadius: 12,
                fontSize: 12,
                color: "#E2E8F0",
              }}
              itemStyle={{ color: "#E2E8F0" }}
              labelStyle={{ color: "#94A3B8" }}
            />
            <Area type="monotone" dataKey="total" stroke="#00D9FF" strokeWidth={2} fill="url(#gTotal)" />
            <Area type="monotone" dataKey="high" stroke="#F59E0B" strokeWidth={1.5} fill="url(#gHigh)" />
            <Area type="monotone" dataKey="critical" stroke="#EF4444" strokeWidth={1.5} fill="url(#gCrit)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}
