import { useMemo } from "react";
import { motion } from "framer-motion";
import {
  ShieldAlert,
  Zap,
  Skull,
  ServerCrash,
  Activity,
} from "lucide-react";
import AnimatedCounter from "../ui/AnimatedCounter";
import { useStore } from "@/lib/store";

export default function KPIStrip() {
  const records = useStore((s) => s.records);
  const lastUpdated = useStore((s) => s.lastUpdated);

  const stats = useMemo(() => {
    const critical = records.filter((r) => r.severity === "CRITICAL").length;
    const kev = records.filter((r) => r.exploited).length;
    const linux = records.filter((r) =>
      ["linux-kernel", "linux-service", "container"].includes(r.category ?? "")
    ).length;
    const new24 = records.filter(
      (r) => Date.now() - new Date(r.published).getTime() < 86400000
    ).length;
    return {
      total: records.length,
      critical,
      kev,
      linux,
      new24,
    };
  }, [records]);

  const kpis = [
    {
      label: "Active CVEs",
      value: stats.total,
      icon: ShieldAlert,
      color: "text-cyber-cyan",
      ring: "from-cyber-cyan/20 to-cyber-cyan/0",
    },
    {
      label: "Critical",
      value: stats.critical,
      icon: Zap,
      color: "text-cyber-red",
      ring: "from-cyber-red/25 to-cyber-red/0",
    },
    {
      label: "Known Exploited",
      value: stats.kev,
      icon: Skull,
      color: "text-cyber-purple",
      ring: "from-cyber-purple/25 to-cyber-purple/0",
    },
    {
      label: "Linux / Infra",
      value: stats.linux,
      icon: ServerCrash,
      color: "text-cyber-amber",
      ring: "from-cyber-amber/25 to-cyber-amber/0",
    },
    {
      label: "New · 24h",
      value: stats.new24,
      icon: Activity,
      color: "text-cyber-green",
      ring: "from-cyber-green/25 to-cyber-green/0",
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
      {kpis.map((k, i) => (
        <motion.div
          key={k.label}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.06 }}
          className="glass glass-hover relative overflow-hidden p-4"
        >
          <div
            className={`absolute -top-10 -right-10 w-32 h-32 rounded-full bg-gradient-to-br ${k.ring} blur-2xl`}
          />
          <div className="flex items-center justify-between relative">
            <div className="text-[10px] uppercase tracking-widest text-slate-500 font-mono">
              {k.label}
            </div>
            <k.icon className={`w-4 h-4 ${k.color}`} />
          </div>
          <div className="font-display text-3xl font-bold text-white mt-2 neon-text">
            <AnimatedCounter value={k.value} />
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-1">
            {lastUpdated
              ? `synced ${new Date(lastUpdated).toLocaleTimeString()}`
              : "awaiting first sync…"}
          </div>
        </motion.div>
      ))}
    </div>
  );
}
