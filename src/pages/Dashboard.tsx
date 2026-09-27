import { useState } from "react";
import { LayoutDashboard } from "lucide-react";
import KPIStrip from "@/components/widgets/KPIStrip";
import ThreatTicker from "@/components/widgets/ThreatTicker";
import SeverityDistribution from "@/components/widgets/SeverityDistribution";
import TrendingVulns from "@/components/widgets/TrendingVulns";
import AssetHeatmap from "@/components/widgets/AssetHeatmap";
import GeoThreatMap from "@/components/widgets/GeoThreatMap";
import TimelineEvents from "@/components/widgets/TimelineEvents";
import ZeroDayPanel from "@/components/widgets/ZeroDayPanel";
import DistroCVEs from "@/components/widgets/DistroCVEs";
import OssMailingPanel from "@/components/widgets/OssMailingPanel";
import CustomizePanel from "@/components/ui/CustomizePanel";
import { useDashboardPrefs } from "@/lib/dashboardLayout";
import { useStore } from "@/lib/store";

export default function Dashboard() {
  const errors = useStore((s) => s.errors);
  const backendOnline = useStore((s) => s.backendOnline);
  const feedBuilding = useStore((s) => s.feedBuilding);
  const { visible, toggle, setAll, reset } = useDashboardPrefs();
  const [customizing, setCustomizing] = useState(false);

  const showSeverity = visible.severity;
  const showTrending = visible.trending;
  const showGeo = visible.geoMap;
  const showHeat = visible.assetHeatmap;
  const showTimeline = visible.timeline;
  const leftStackHasAny = showGeo || showHeat;
  const rightStackHasAny = showTimeline;
  const anyVisible = Object.values(visible).some(Boolean);

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-white tracking-wide">
            Operations Overview
          </h1>
          <p className="text-[12px] text-slate-500 font-mono">
            Live synthesis of CVE intelligence · NVD · OSV · CISA KEV · GitHub PoCs · trickest/cve · Exploit-DB · Nuclei templates · FIRST EPSS
          </p>
        </div>
        <button
          onClick={() => setCustomizing(true)}
          className="shrink-0 h-9 px-3 rounded-lg border border-white/10 hover:border-cyber-cyan/50 hover:text-white text-slate-300 text-[12px] font-mono flex items-center gap-2 transition"
          title="Choose which widgets to show"
        >
          <LayoutDashboard className="w-4 h-4" />
          Customize
        </button>
      </div>

      {backendOnline && feedBuilding && (
        <div className="glass border border-cyber-cyan/30 px-4 py-3 text-[12px] font-mono text-cyber-cyan flex items-start gap-3">
          <span className="shrink-0 animate-pulse">⟳</span>
          <div>
            <div className="text-white font-semibold">Building CVE feed — fetching NVD, KEV, PoCs, EPSS…</div>
            <div className="text-slate-400 mt-1">
              First startup pulls up to 60 days of data. The dashboard will populate automatically once the build completes (usually 1–3 min).
            </div>
          </div>
        </div>
      )}

      {!backendOnline && (
        <div className="glass border border-cyber-amber/30 px-4 py-3 text-[12px] font-mono text-cyber-amber flex items-start gap-3">
          <span className="shrink-0">⚠</span>
          <div>
            <div className="text-white font-semibold">PoC / Exploit-DB / 0-day correlation backend is offline.</div>
            <div className="text-slate-400 mt-1">
              Run <code className="text-cyber-cyan">npm run dev:server</code> (in another shell) to enable GitHub PoC indexing, Exploit-DB lookup, and inthewild.io enrichment. Without it the dashboard falls back to NVD + OSV + KEV only.
            </div>
          </div>
        </div>
      )}

      {errors.length > 0 && (
        <div className="glass border border-cyber-amber/30 px-4 py-2 text-[11px] font-mono text-cyber-amber">
          {errors.length} source(s) degraded:{" "}
          <span className="text-slate-400">{errors.join(" · ")}</span>
        </div>
      )}

      {visible.kpi && <KPIStrip />}

      {visible.ticker && <ThreatTicker />}

      {(showSeverity || showTrending) && (
        <div
          className={
            showSeverity && showTrending
              ? "grid grid-cols-1 xl:grid-cols-3 gap-4"
              : "grid grid-cols-1 gap-4"
          }
        >
          {showSeverity && <SeverityDistribution />}
          {showTrending && (
            <div className={showSeverity ? "xl:col-span-2" : ""}>
              <TrendingVulns />
            </div>
          )}
        </div>
      )}

      {visible.distroCves && <DistroCVEs />}

      {visible.ossMailing && <OssMailingPanel />}

      {visible.zeroDay && <ZeroDayPanel />}

      {(leftStackHasAny || rightStackHasAny) && (
        <div
          className={
            leftStackHasAny && rightStackHasAny
              ? "grid grid-cols-1 xl:grid-cols-3 gap-4"
              : "grid grid-cols-1 gap-4"
          }
        >
          {leftStackHasAny && (
            <div
              className={
                rightStackHasAny ? "xl:col-span-2 space-y-4" : "space-y-4"
              }
            >
              {showGeo && <GeoThreatMap />}
              {showHeat && <AssetHeatmap />}
            </div>
          )}
          {rightStackHasAny && (
            <div className="space-y-4">
              {showTimeline && <TimelineEvents />}
            </div>
          )}
        </div>
      )}

      {!anyVisible && (
        <div className="glass border border-white/10 rounded-xl p-10 text-center">
          <LayoutDashboard className="w-8 h-8 text-slate-600 mx-auto mb-3" />
          <div className="text-slate-300 text-sm mb-1">All widgets are hidden</div>
          <div className="text-slate-500 text-[12px] mb-4">
            Open <span className="text-cyber-cyan">Customize</span> to bring widgets back.
          </div>
          <button
            onClick={() => setCustomizing(true)}
            className="px-3 h-8 rounded-md border border-cyber-cyan/40 text-cyber-cyan text-[12px] font-mono hover:bg-cyber-cyan/10 transition"
          >
            Customize
          </button>
        </div>
      )}

      <CustomizePanel
        open={customizing}
        onClose={() => setCustomizing(false)}
        visible={visible}
        onToggle={toggle}
        onSetAll={setAll}
        onReset={reset}
      />
    </div>
  );
}
