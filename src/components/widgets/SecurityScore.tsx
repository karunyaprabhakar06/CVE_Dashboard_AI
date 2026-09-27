import { useEffect, useState } from "react";
import {
  RadialBarChart,
  RadialBar,
  ResponsiveContainer,
  PolarAngleAxis,
} from "recharts";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";

export default function SecurityScore() {
  const records = useStore((s) => s.records);
  const [score, setScore] = useState(78);

  useEffect(() => {
    if (records.length === 0) return;
    const crit = records.filter((r) => r.severity === "CRITICAL").length;
    const exploited = records.filter((r) => r.exploited).length;
    const base = 100 - Math.min(40, crit / 2) - Math.min(20, exploited / 3);
    setScore(Math.max(20, Math.round(base)));
  }, [records]);

  const color =
    score >= 80 ? "#10B981" : score >= 60 ? "#F59E0B" : "#EF4444";

  return (
    <Panel
      title="Security Posture Score"
      subtitle="Composite SOC readiness index"
      accent="green"
      delay={0.3}
    >
      <div className="relative h-[200px]">
        <ResponsiveContainer>
          <RadialBarChart
            innerRadius="70%"
            outerRadius="100%"
            data={[{ name: "score", value: score, fill: color }]}
            startAngle={220}
            endAngle={-40}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
            <RadialBar background={{ fill: "#1F2A40" }} dataKey="value" cornerRadius={20} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="font-display text-5xl font-bold neon-text" style={{ color }}>
            {score}
          </div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">
            of 100
          </div>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-2 mt-3 text-center">
        {[
          { l: "Coverage", v: "92%" },
          { l: "Detection", v: "87%" },
          { l: "Response", v: "74%" },
        ].map((x) => (
          <div key={x.l} className="rounded-lg bg-white/[0.02] border border-white/5 py-2">
            <div className="text-[10px] uppercase font-mono text-slate-500">{x.l}</div>
            <div className="font-display font-semibold text-white">{x.v}</div>
          </div>
        ))}
      </div>
    </Panel>
  );
}
