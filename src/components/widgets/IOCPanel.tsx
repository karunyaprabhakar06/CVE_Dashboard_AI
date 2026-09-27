import Panel from "../ui/Panel";
import { Globe, Hash, Server, Mail, Fingerprint } from "lucide-react";

const IOCS = [
  { type: "IP", value: "185.220.101.42", country: "RU", hits: 1284, icon: Globe, color: "text-cyber-red" },
  { type: "Domain", value: "auth-microsoft[.]sec-login.io", country: "—", hits: 412, icon: Globe, color: "text-cyber-amber" },
  { type: "Hash", value: "a3f5…b91c (SHA256)", country: "—", hits: 92, icon: Hash, color: "text-cyber-cyan" },
  { type: "Host", value: "c2.northshell[.]net", country: "KP", hits: 73, icon: Server, color: "text-cyber-red" },
  { type: "Email", value: "billing@invoice-pay[.]co", country: "—", hits: 318, icon: Mail, color: "text-cyber-amber" },
  { type: "TLS", value: "JA3 e7d705a3286e19ea…", country: "—", hits: 41, icon: Fingerprint, color: "text-cyber-cyan" },
];

export default function IOCPanel() {
  return (
    <Panel
      title="IOC Monitoring"
      subtitle="Indicators observed across edge sensors"
      accent="amber"
      delay={0.32}
    >
      <ul className="divide-y divide-white/5">
        {IOCS.map((i) => (
          <li
            key={i.value}
            className="flex items-center gap-3 py-2 group hover:bg-white/[0.02] -mx-2 px-2 rounded-lg transition"
          >
            <div className={`w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center ${i.color}`}>
              <i.icon className="w-4 h-4" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">
                {i.type} · {i.country}
              </div>
              <div className="text-[12px] font-mono text-white truncate">{i.value}</div>
            </div>
            <div className="text-right">
              <div className="font-display text-sm font-semibold text-white">
                {i.hits.toLocaleString()}
              </div>
              <div className="text-[10px] text-slate-500 font-mono">hits/24h</div>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
