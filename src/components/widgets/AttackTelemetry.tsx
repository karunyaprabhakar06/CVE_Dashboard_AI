import { useEffect, useMemo, useState } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";

export default function AttackTelemetry() {
  const records = useStore((s) => s.records);
  const [series, setSeries] = useState<{ t: string; events: number; blocked: number }[]>(
    () => {
      const arr = [];
      for (let i = 30; i >= 0; i--) {
        arr.push({
          t: new Date(Date.now() - i * 2000).toLocaleTimeString().slice(0, 8),
          events: Math.floor(Math.random() * 80 + 40),
          blocked: Math.floor(Math.random() * 50 + 20),
        });
      }
      return arr;
    }
  );

  useEffect(() => {
    const id = setInterval(() => {
      setSeries((prev) => {
        const base = records.length || 50;
        const next = [
          ...prev.slice(1),
          {
            t: new Date().toLocaleTimeString().slice(0, 8),
            events: Math.floor(Math.random() * (base / 2) + base / 2),
            blocked: Math.floor(Math.random() * (base / 3) + base / 4),
          },
        ];
        return next;
      });
    }, 2000);
    return () => clearInterval(id);
  }, [records.length]);

  const peak = useMemo(() => Math.max(...series.map((s) => s.events)), [series]);

  return (
    <Panel
      title="Real-time Attack Telemetry"
      subtitle="Edge sensor stream · 2s tick"
      accent="cyan"
      delay={0.1}
      right={
        <div className="flex items-center gap-3 text-[10px] font-mono">
          <span className="flex items-center gap-1.5 text-cyber-cyan">
            <span className="w-2 h-2 bg-cyber-cyan rounded-full" /> events
          </span>
          <span className="flex items-center gap-1.5 text-cyber-green">
            <span className="w-2 h-2 bg-cyber-green rounded-full" /> blocked
          </span>
          <span className="text-slate-500">peak {peak}/s</span>
        </div>
      }
    >
      <div className="h-[220px]">
        <ResponsiveContainer>
          <LineChart data={series} margin={{ top: 10, right: 12, left: -18, bottom: 0 }}>
            <CartesianGrid stroke="#1F2A40" strokeDasharray="3 6" vertical={false} />
            <XAxis dataKey="t" stroke="#475569" fontSize={9} tickLine={false} axisLine={false} />
            <YAxis stroke="#475569" fontSize={9} tickLine={false} axisLine={false} />
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
            <Line
              type="monotone"
              dataKey="events"
              stroke="#00D9FF"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
            <Line
              type="monotone"
              dataKey="blocked"
              stroke="#10B981"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}
