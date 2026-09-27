import { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
  Cell,
} from "recharts";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";

export default function EPSSChart() {
  const records = useStore((s) => s.records);

  const data = useMemo(() => {
    const buckets = [
      { name: "0–10%", min: 0, max: 0.1, count: 0 },
      { name: "10–25%", min: 0.1, max: 0.25, count: 0 },
      { name: "25–50%", min: 0.25, max: 0.5, count: 0 },
      { name: "50–75%", min: 0.5, max: 0.75, count: 0 },
      { name: "75–90%", min: 0.75, max: 0.9, count: 0 },
      { name: "90–100%", min: 0.9, max: 1.01, count: 0 },
    ];
    for (const r of records) {
      const e = r.epss ?? 0;
      for (const b of buckets) {
        if (e >= b.min && e < b.max) {
          b.count++;
          break;
        }
      }
    }
    return buckets;
  }, [records]);

  const palette = ["#10B981", "#10B981", "#00D9FF", "#F59E0B", "#F59E0B", "#EF4444"];

  return (
    <Panel
      title="EPSS Exploit Probability"
      subtitle="Likelihood of exploitation in next 30 days"
      accent="purple"
      delay={0.15}
    >
      <div className="h-[220px]">
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 10, right: 8, left: -16, bottom: 0 }}>
            <XAxis dataKey="name" stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
            <YAxis stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
            <Tooltip
              cursor={{ fill: "rgba(255,255,255,0.04)" }}
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
            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
              {data.map((_, i) => (
                <Cell key={i} fill={palette[i]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}
