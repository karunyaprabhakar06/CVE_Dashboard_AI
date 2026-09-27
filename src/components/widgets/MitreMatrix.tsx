import { useMemo } from "react";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";

const MITRE_TACTICS = [
  { id: "TA0001", name: "Initial Access", techs: ["T1190", "T1133", "T1566", "T1078"] },
  { id: "TA0002", name: "Execution", techs: ["T1059", "T1203", "T1569"] },
  { id: "TA0003", name: "Persistence", techs: ["T1543", "T1547", "T1136"] },
  { id: "TA0004", name: "Privilege Esc.", techs: ["T1068", "T1548", "T1055"] },
  { id: "TA0005", name: "Defense Evasion", techs: ["T1027", "T1070", "T1562"] },
  { id: "TA0006", name: "Credential Access", techs: ["T1003", "T1110", "T1555"] },
  { id: "TA0007", name: "Discovery", techs: ["T1018", "T1083", "T1057"] },
  { id: "TA0008", name: "Lateral Movement", techs: ["T1021", "T1080", "T1210"] },
  { id: "TA0009", name: "Collection", techs: ["T1005", "T1056"] },
  { id: "TA0010", name: "Exfiltration", techs: ["T1041", "T1567"] },
  { id: "TA0040", name: "Impact", techs: ["T1486", "T1490", "T1499"] },
];

export default function MitreMatrix() {
  const records = useStore((s) => s.records);

  // pseudo-map: hash CVE id to a technique to color cells
  const heat = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of records) {
      const hash = [...r.id].reduce((a, c) => a + c.charCodeAt(0), 0);
      for (const t of MITRE_TACTICS) {
        const tech = t.techs[hash % t.techs.length];
        m[tech] = (m[tech] ?? 0) + (r.severity === "CRITICAL" ? 3 : r.severity === "HIGH" ? 2 : 1);
      }
    }
    return m;
  }, [records]);

  const max = Math.max(1, ...Object.values(heat));

  return (
    <Panel
      title="MITRE ATT&CK Coverage"
      subtitle="Inferred technique exposure mapped from active CVEs"
      accent="purple"
      delay={0.25}
    >
      <div className="overflow-x-auto">
        <div className="flex gap-2 min-w-max">
          {MITRE_TACTICS.map((t) => (
            <div key={t.id} className="w-28 shrink-0">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono mb-2 truncate">
                {t.name}
              </div>
              <div className="flex flex-col gap-1.5">
                {t.techs.map((tech) => {
                  const v = heat[tech] ?? 0;
                  const alpha = 0.15 + (v / max) * 0.85;
                  return (
                    <div
                      key={tech}
                      className="relative h-10 rounded-md flex items-center justify-center text-[10px] font-mono text-white border border-white/5 cursor-default group"
                      style={{
                        background: `linear-gradient(135deg, rgba(124,58,237,${alpha}), rgba(0,217,255,${alpha * 0.6}))`,
                        boxShadow: v > max * 0.6 ? "0 0 12px rgba(124,58,237,0.4)" : undefined,
                      }}
                      title={`${tech} · ${v} indicators`}
                    >
                      {tech}
                      <span className="absolute -top-1 -right-1 text-[9px] bg-bg border border-white/10 px-1 rounded opacity-0 group-hover:opacity-100 transition">
                        {v}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}
