// Dashboard widget layout/visibility preferences.
// Stored in localStorage so the user's "what should be on my dashboard" choice
// survives reloads. Order is fixed for now; visibility is toggle-able.
import { useCallback, useEffect, useState } from "react";

export type WidgetId =
  | "kpi"
  | "ticker"
  | "severity"
  | "trending"
  | "distroCves"
  | "ossMailing"
  | "zeroDay"
  | "geoMap"
  | "assetHeatmap"
  | "timeline";

export interface WidgetMeta {
  id: WidgetId;
  label: string;
  description: string;
  group: "overview" | "vulns" | "intel";
}

export const WIDGET_REGISTRY: WidgetMeta[] = [
  { id: "kpi", label: "KPI Strip", description: "Top-line counters", group: "overview" },
  { id: "ticker", label: "Threat Ticker", description: "Scrolling latest CVEs", group: "overview" },
  { id: "severity", label: "Severity Distribution", description: "Donut breakdown", group: "vulns" },
  { id: "trending", label: "Trending Vulnerabilities", description: "Hot CVEs right now", group: "vulns" },
  { id: "distroCves", label: "Linux Distribution CVEs", description: "Services affected per severity", group: "vulns" },
  { id: "ossMailing", label: "OSS Mailing Early Threats", description: "oss-security posts including no-CVE signals", group: "intel" },
  { id: "zeroDay", label: "Zero-Day Panel", description: "Active 0-days in the wild", group: "intel" },
  { id: "geoMap", label: "Geo Threat Map", description: "Geo-attributed attack sources", group: "intel" },
  { id: "assetHeatmap", label: "Asset Heatmap", description: "Per-asset risk heatmap", group: "intel" },
  { id: "timeline", label: "Timeline Events", description: "Recent security events", group: "intel" },
];

const STORAGE_KEY = "sg-dashboard-visible-widgets-v1";

function loadPrefs(): Record<WidgetId, boolean> {
  const defaults = Object.fromEntries(
    WIDGET_REGISTRY.map((w) => [w.id, true])
  ) as Record<WidgetId, boolean>;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaults;
    const parsed = JSON.parse(raw) as Record<string, boolean>;
    for (const w of WIDGET_REGISTRY) {
      if (typeof parsed[w.id] === "boolean") defaults[w.id] = parsed[w.id];
    }
    return defaults;
  } catch {
    return defaults;
  }
}

export function useDashboardPrefs() {
  const [visible, setVisible] = useState<Record<WidgetId, boolean>>(loadPrefs);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(visible));
    } catch {
      // ignore quota errors
    }
  }, [visible]);

  const toggle = useCallback((id: WidgetId) => {
    setVisible((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const setAll = useCallback((value: boolean) => {
    setVisible(
      Object.fromEntries(WIDGET_REGISTRY.map((w) => [w.id, value])) as Record<
        WidgetId,
        boolean
      >
    );
  }, []);

  const reset = useCallback(() => setAll(true), [setAll]);

  return { visible, toggle, setAll, reset };
}
