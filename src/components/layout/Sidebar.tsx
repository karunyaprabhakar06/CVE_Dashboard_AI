import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

const items = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/cves", label: "CVEs", icon: ShieldAlert },
];

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  return (
    <aside
      className={cn(
        "sticky top-0 h-screen shrink-0 border-r border-white/5 bg-bg-panel/40 backdrop-blur-xl transition-all duration-300 z-20",
        collapsed ? "w-[72px]" : "w-[240px]"
      )}
    >
      <div className="flex items-center gap-2 px-4 h-16 border-b border-white/5">
        <div className="relative">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyber-cyan to-cyber-purple flex items-center justify-center shadow-glow">
            <ShieldAlert className="w-5 h-5 text-bg" />
          </div>
          <span className="absolute inset-0 rounded-xl ring-1 ring-cyber-cyan/40 animate-pulseRing" />
        </div>
        {!collapsed && (
          <div className="leading-tight">
            <div className="font-display font-semibold text-white tracking-wide">
              CTI
            </div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-cyber-cyan/80 font-mono">
              CVE Threat Intelligence
            </div>
          </div>
        )}
      </div>

      <nav className="p-3 flex flex-col gap-1">
        {items.map((it) => (
          <NavLink
            key={it.to}
            to={it.to}
            className={({ isActive }) =>
              cn(
                "group relative flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all",
                "text-slate-400 hover:text-white hover:bg-white/[0.04]",
                isActive &&
                  "text-white bg-gradient-to-r from-cyber-cyan/10 to-cyber-purple/10 border border-cyber-cyan/20 shadow-glow"
              )
            }
          >
            <it.icon className="w-[18px] h-[18px] shrink-0" />
            {!collapsed && <span>{it.label}</span>}
            {!collapsed && it.to === "/cves" && (
              <span className="ml-auto chip border-cyber-cyan/30 text-cyber-cyan bg-cyber-cyan/10">
                LIVE
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      <button
        onClick={() => setCollapsed((v) => !v)}
        className="absolute bottom-4 left-1/2 -translate-x-1/2 p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition"
        title="Collapse"
      >
        {collapsed ? (
          <ChevronsRight className="w-4 h-4" />
        ) : (
          <ChevronsLeft className="w-4 h-4" />
        )}
      </button>
    </aside>
  );
}
