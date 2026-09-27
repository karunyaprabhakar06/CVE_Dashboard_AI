import { useMemo } from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";
import { SEVERITY_COLORS } from "@/lib/utils";

export default function SeverityDistribution() {
  const records = useStore((s) => s.records);

  const data = useMemo(() => {
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      NONE: 0,
    };
    for (const r of records) counts[r.severity]++;
    return Object.entries(counts)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => ({ name: k, value: v }));
  }, [records]);

  const total = data.reduce((a, b) => a + b.value, 0);

  return (
    <Panel
      title="CVE Severity Distribution"
      subtitle="Aggregated across NVD · OSV · KEV · ThreatTracer"
      accent="red"
      delay={0.05}
    >
      <div className="relative h-[220px]">
        <ResponsiveContainer>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={62}
              outerRadius={92}
              paddingAngle={2}
              stroke="none"
            >
              {data.map((d) => (
                <Cell key={d.name} fill={SEVERITY_COLORS[d.name]} />
              ))}
            </Pie>
            <Tooltip
              position={{ x: 0, y: 0 }}
              wrapperStyle={{ zIndex: 50, outline: "none", pointerEvents: "none" }}
              cursor={false}
              content={({ active, payload }) => {
                if (!active || !payload || !payload.length) return null;
                const p = payload[0];
                const name = String(p.name ?? "");
                const value = Number(p.value ?? 0);
                const pct = total > 0 ? ((value / total) * 100).toFixed(1) : "0";
                const color = SEVERITY_COLORS[name] ?? "#E2E8F0";
                return (
                  <div
                    style={{
                      background: "#0B1020",
                      border: `1px solid ${color}55`,
                      borderRadius: 12,
                      padding: "8px 12px",
                      fontSize: 12,
                      color: "#E2E8F0",
                      boxShadow: "0 4px 18px rgba(0,0,0,0.45)",
                      minWidth: 130,
                    }}
                  >
                    <div
                      style={{
                        color,
                        fontFamily: "monospace",
                        fontSize: 10,
                        letterSpacing: "0.12em",
                        textTransform: "uppercase",
                        marginBottom: 2,
                      }}
                    >
                      {name}
                    </div>
                    <div style={{ fontWeight: 600, fontSize: 15 }}>
                      {value.toLocaleString()}
                    </div>
                    <div style={{ color: "#94A3B8", fontSize: 11, marginTop: 2 }}>
                      {pct}% of total
                    </div>
                  </div>
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <div className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">
            Total
          </div>
          <div className="font-display text-3xl font-bold text-white neon-text">
            {total.toLocaleString()}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">CVEs tracked</div>
        </div>
      </div>
      <div className="grid grid-cols-5 gap-2 mt-4">
        {["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].map((sev) => {
          const v = data.find((d) => d.name === sev)?.value ?? 0;
          return (
            <div
              key={sev}
              className="text-center rounded-lg bg-white/[0.02] border border-white/5 py-2"
            >
              <div
                className="text-[10px] font-mono uppercase tracking-wider"
                style={{ color: SEVERITY_COLORS[sev] }}
              >
                {sev}
              </div>
              <div className="font-display text-lg font-semibold text-white">
                {v}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
