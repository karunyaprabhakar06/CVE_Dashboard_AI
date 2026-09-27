import { useMemo } from "react";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";

const CATEGORIES = [
  "linux-kernel",
  "linux-service",
  "web-server",
  "crypto-lib",
  "container",
  "windows",
  "mobile-os",
  "network",
  "cms",
  "web-app",
  "general",
];

const ZONES = ["Edge", "DMZ", "Internal", "Cloud", "Endpoint", "OT/IoT"];

export default function AssetHeatmap() {
  const records = useStore((s) => s.records);

  const data = useMemo(() => {
    const matrix: number[][] = ZONES.map(() => CATEGORIES.map(() => 0));
    for (const r of records) {
      const cIdx = CATEGORIES.indexOf(r.category ?? "general");
      if (cIdx < 0) continue;
      const hash = [...r.id].reduce((a, c) => a + c.charCodeAt(0), 0);
      const zIdx = hash % ZONES.length;
      const w =
        r.severity === "CRITICAL"
          ? 4
          : r.severity === "HIGH"
            ? 3
            : r.severity === "MEDIUM"
              ? 2
              : 1;
      matrix[zIdx][cIdx] += w;
    }
    const max = Math.max(1, ...matrix.flat());
    return { matrix, max };
  }, [records]);

  return (
    <Panel
      title="Asset Exposure Heatmap"
      subtitle="Severity-weighted CVE pressure by zone × category"
      accent="amber"
      delay={0.2}
    >
      <div className="overflow-x-auto">
        <table className="text-[10px] font-mono w-full min-w-[680px]">
          <thead>
            <tr>
              <th className="text-left text-slate-500 p-1.5 font-normal"></th>
              {CATEGORIES.map((c) => (
                <th
                  key={c}
                  className="text-left text-slate-500 p-1.5 font-normal whitespace-nowrap"
                >
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ZONES.map((z, zi) => (
              <tr key={z}>
                <td className="text-slate-300 p-1.5 pr-3 font-semibold whitespace-nowrap">
                  {z}
                </td>
                {CATEGORIES.map((_, ci) => {
                  const v = data.matrix[zi][ci];
                  const intensity = v / data.max;
                  const color =
                    intensity > 0.66
                      ? "239,68,68"
                      : intensity > 0.33
                        ? "245,158,11"
                        : intensity > 0
                          ? "0,217,255"
                          : "30,41,59";
                  return (
                    <td key={ci} className="p-0.5">
                      <div
                        className="h-8 rounded-md flex items-center justify-center text-white/90 transition hover:scale-105"
                        style={{
                          background: `rgba(${color}, ${0.1 + intensity * 0.8})`,
                          boxShadow:
                            intensity > 0.5
                              ? `0 0 10px rgba(${color},0.4)`
                              : undefined,
                        }}
                        title={`${z} · ${CATEGORIES[ci]} · score ${v}`}
                      >
                        {v > 0 ? v : ""}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
