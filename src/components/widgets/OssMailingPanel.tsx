import { useEffect, useMemo, useRef, useState } from "react";
import { ExternalLink, MessageSquareWarning, CheckCheck } from "lucide-react";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";
import { SEVERITY_COLORS, timeAgo } from "@/lib/utils";

const READ_STORAGE_KEY = "zsg-oss-mailing-read-v1";
const PANEL_SIZE_STORAGE_KEY = "zsg-oss-mailing-panel-size-v1";
const SOURCE_TAB_STORAGE_KEY = "zsg-threat-tab-v1";
const DEFAULT_VISIBLE = 10;
const MIN_WIDTH = 460;
const MIN_HEIGHT = 320;
const PRIMARY_FRESHNESS_DAYS: Record<SourceTab, number> = {
  "OSS-SEC": 14,
  MITRE: 7,
  NVD: 7,
};

type SourceTab = "OSS-SEC" | "MITRE" | "NVD";

interface AlertItem {
  id: string;
  readKey: string;
  title: string;
  description?: string;
  published: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  link: string;
  cveText: string;
  source: SourceTab;
  likelyLinux?: boolean;
}

function toEpoch(input?: string) {
  const ts = new Date(input ?? 0).getTime();
  return Number.isFinite(ts) ? ts : 0;
}

function recentThreats<T extends { id: string; published?: string; modified?: string }>(
  rows: T[],
  maxAgeDays: number,
  fallbackNow = Date.now()
) {
  // Deduplicate by CVE ID first, keeping the freshest threat timestamp.
  const byId = new Map<string, T>();
  for (const r of rows) {
    const prev = byId.get(r.id);
    if (!prev) {
      byId.set(r.id, r);
      continue;
    }
    const prevScore = Math.max(toEpoch(prev.published), toEpoch(prev.modified));
    const nextScore = Math.max(toEpoch(r.published), toEpoch(r.modified));
    if (nextScore > prevScore) byId.set(r.id, r);
  }
  const cutoff = fallbackNow - maxAgeDays * 86_400_000;

  return [...byId.values()]
    .filter((r) => Math.max(toEpoch(r.published), toEpoch(r.modified)) >= cutoff)
    .sort((a, b) => {
      const aFresh = Math.max(toEpoch(a.published), toEpoch(a.modified));
      const bFresh = Math.max(toEpoch(b.published), toEpoch(b.modified));
      return bFresh - aFresh;
    });
}

function withFreshnessWindow<T extends { id: string; published?: string; modified?: string }>(
  rows: T[],
  tab: SourceTab
) {
  const primaryDays = PRIMARY_FRESHNESS_DAYS[tab];
  const primary = recentThreats(rows, primaryDays);
  return {
    rows: primary,
    days: primaryDays,
    usedFallback: false,
  };
}

export default function OssMailingPanel() {
  const signals = useStore((s) => s.ossMailing);
  const records = useStore((s) => s.records);
  const panelRef = useRef<HTMLDivElement>(null);

  const [readIds, setReadIds] = useState<string[]>(() => {
    if (typeof window === "undefined") return [];
    try {
      const raw = window.localStorage.getItem(READ_STORAGE_KEY);
      return raw ? (JSON.parse(raw) as string[]) : [];
    } catch {
      return [];
    }
  });

  const [panelSize, setPanelSize] = useState<{ width: number | null; height: number | null }>(() => {
    if (typeof window === "undefined") return { width: null, height: null };
    try {
      const raw = window.localStorage.getItem(PANEL_SIZE_STORAGE_KEY);
      if (!raw) return { width: null, height: null };
      const parsed = JSON.parse(raw) as { width?: number; height?: number };
      return {
        width: Number.isFinite(parsed.width) ? Math.max(MIN_WIDTH, parsed.width!) : null,
        height: Number.isFinite(parsed.height) ? Math.max(MIN_HEIGHT, parsed.height!) : null,
      };
    } catch {
      return { width: null, height: null };
    }
  });

  const [activeTab, setActiveTab] = useState<SourceTab>(() => {
    if (typeof window === "undefined") return "OSS-SEC";
    try {
      const raw = window.localStorage.getItem(SOURCE_TAB_STORAGE_KEY);
      return raw === "MITRE" || raw === "NVD"
        ? raw
        : "OSS-SEC";
    } catch {
      return "OSS-SEC";
    }
  });

  const itemsByTab = useMemo(() => {
    const oss: AlertItem[] = signals.map((s) => ({
      id: s.id,
      readKey: `OSS-SEC:${s.id}`,
      title: s.subject,
      description: undefined,
      published: s.published,
      severity: s.severity,
      link: s.link,
      cveText: s.cveIds.length ? s.cveIds.join(", ") : "NO-CVE-YET",
      source: "OSS-SEC",
      likelyLinux: s.likelyLinux,
    }));

    const pickLink = (r: (typeof records)[number]) =>
      r.references?.[0] ||
      (r.source === "MITRE"
        ? `https://www.cve.org/CVERecord?id=${r.id}`
        : `https://nvd.nist.gov/vuln/detail/${r.id}`);

    const mapRecord = (r: (typeof records)[number], source: SourceTab): AlertItem => ({
      id: r.id,
      readKey: `${source}:${r.id}`,
      title: r.id,
      description: r.description,
      published: r.modified || r.published,
      severity: r.severity,
      link: pickLink(r),
      cveText: r.id,
      source,
    });

    const mitreResult = withFreshnessWindow(
      records.filter((r) => r.source === "MITRE"),
      "MITRE"
    );
    const nvdResult = withFreshnessWindow(
      records.filter((r) => r.source === "NVD"),
      "NVD"
    );

    const mitre = mitreResult.rows
      .slice(0, 160)
      .map((r) => mapRecord(r, "MITRE"));
    const nvd = nvdResult.rows
      .slice(0, 220)
      .map((r) => mapRecord(r, "NVD"));

    return {
      "OSS-SEC": oss,
      MITRE: mitre,
      NVD: nvd,
      __windowDays: {
        "OSS-SEC": PRIMARY_FRESHNESS_DAYS["OSS-SEC"],
        MITRE: mitreResult.days,
        NVD: nvdResult.days,
      },
      __fallback: {
        "OSS-SEC": false,
        MITRE: mitreResult.usedFallback,
        NVD: nvdResult.usedFallback,
      },
    } satisfies Record<SourceTab, AlertItem[]> & {
      __windowDays: Record<SourceTab, number>;
      __fallback: Record<SourceTab, boolean>;
    };
  }, [signals, records]);

  const windowDaysByTab = useMemo(
    () =>
      (itemsByTab as unknown as {
        __windowDays?: Record<SourceTab, number>;
      }).__windowDays ?? PRIMARY_FRESHNESS_DAYS,
    [itemsByTab]
  );

  const fallbackByTab = useMemo(
    () =>
      (itemsByTab as unknown as {
        __fallback?: Record<SourceTab, boolean>;
      }).__fallback ?? {
        "OSS-SEC": false,
        MITRE: false,
        NVD: false,
      },
    [itemsByTab]
  );

  const items = useMemo(
    () => itemsByTab[activeTab].slice(0, DEFAULT_VISIBLE),
    [itemsByTab, activeTab]
  );

  const tabMeta = useMemo(() => {
    const unreadFor = (tab: SourceTab) =>
      itemsByTab[tab]
        .slice(0, DEFAULT_VISIBLE)
        .filter((i) => !readIds.includes(i.readKey)).length;
    return {
      "OSS-SEC": { label: "OSS", unread: unreadFor("OSS-SEC") },
      MITRE: { label: "MITRE", unread: unreadFor("MITRE") },
      NVD: { label: "NVD", unread: unreadFor("NVD") },
    } satisfies Record<SourceTab, { label: string; unread: number }>;
  }, [itemsByTab, readIds]);

  const unreadCount = useMemo(
    () => items.filter((item) => !readIds.includes(item.readKey)).length,
    [items, readIds]
  );

  useEffect(() => {
    try {
      window.localStorage.setItem(READ_STORAGE_KEY, JSON.stringify(readIds));
    } catch {
      // ignore storage failures
    }
  }, [readIds]);

  useEffect(() => {
    try {
      window.localStorage.setItem(PANEL_SIZE_STORAGE_KEY, JSON.stringify(panelSize));
    } catch {
      // ignore storage failures
    }
  }, [panelSize]);

  useEffect(() => {
    try {
      window.localStorage.setItem(SOURCE_TAB_STORAGE_KEY, activeTab);
    } catch {
      // ignore storage failures
    }
  }, [activeTab]);

  const markRead = (key: string) => {
    setReadIds((prev) => (prev.includes(key) ? prev : [...prev, key]));
  };

  const markAllAsRead = () => {
    setReadIds((prev) => {
      const currentTabItems = items.map((item) => item.readKey);
      const newReadIds = new Set(prev);
      currentTabItems.forEach((key) => newReadIds.add(key));
      return Array.from(newReadIds);
    });
  };

  const startResize = (mode: "right" | "bottom" | "corner") =>
    (event: React.MouseEvent<HTMLDivElement>) => {
      event.preventDefault();
      event.stopPropagation();
      const panel = panelRef.current;
      if (!panel) return;

      const rect = panel.getBoundingClientRect();
      const parentWidth = panel.parentElement?.clientWidth ?? rect.width;
      const startX = event.clientX;
      const startY = event.clientY;
      const startWidth = rect.width;
      const startHeight = rect.height;

      const onMove = (moveEvent: MouseEvent) => {
        const nextWidth =
          mode === "bottom"
            ? startWidth
            : Math.min(parentWidth, Math.max(MIN_WIDTH, startWidth + moveEvent.clientX - startX));
        const nextHeight =
          mode === "right"
            ? startHeight
            : Math.min(Math.floor(window.innerHeight * 0.82), Math.max(MIN_HEIGHT, startHeight + moveEvent.clientY - startY));
        setPanelSize((prev) => ({
          width: mode === "bottom" ? prev.width : nextWidth,
          height: mode === "right" ? prev.height : nextHeight,
        }));
      };

      const onUp = () => {
        window.removeEventListener("mousemove", onMove);
        window.removeEventListener("mouseup", onUp);
      };

      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    };

  return (
    <div
      ref={panelRef}
      className="relative max-w-full"
      style={{
        width: panelSize.width ? `${panelSize.width}px` : undefined,
        height: panelSize.height ? `${panelSize.height}px` : undefined,
        minHeight: `${MIN_HEIGHT}px`,
      }}
    >
      <Panel
        title="New Threat Alerts"
        subtitle="OSS / MITRE / NVD in one mailing-style view"
        accent="amber"
        delay={0.2}
        className="h-full flex flex-col"
        bodyClassName="flex-1 overflow-auto"
        right={
          <div className="flex items-center gap-2">
            <button
              onClick={markAllAsRead}
              disabled={unreadCount === 0}
              className="h-7 px-3 rounded-md border border-cyber-amber/30 text-cyber-amber bg-cyber-amber/10 font-mono hover:bg-cyber-amber/20 hover:border-cyber-amber/50 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-cyber-amber/10 disabled:hover:border-cyber-amber/30 transition flex items-center justify-center"
              title={unreadCount === 0 ? "All items are read" : "Mark all as read for current tab"}
            >
              <CheckCheck className="w-4 h-4" />
            </button>
            <span className="chip border-cyber-amber/30 text-cyber-amber bg-cyber-amber/10 font-mono">
              <MessageSquareWarning className="w-3 h-3" /> {unreadCount}/{DEFAULT_VISIBLE}
            </span>
          </div>
        }
      >
      <div className="space-y-2.5">
        <div className="flex flex-wrap items-center gap-1.5">
          {(["OSS-SEC", "MITRE", "NVD"] as SourceTab[]).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={
                "h-6 px-2 rounded-md border text-[10px] font-mono transition flex items-center gap-1 " +
                (activeTab === tab
                  ? "border-cyber-amber/60 bg-cyber-amber/10 text-cyber-amber"
                  : "border-white/10 bg-black/20 text-slate-400 hover:text-white hover:border-cyber-amber/40")
              }
            >
              {tabMeta[tab].label}
              {tabMeta[tab].unread > 0 && (
                <span className="min-w-[14px] h-[14px] px-1 rounded-full bg-cyber-red text-white text-[9px] font-bold flex items-center justify-center">
                  {tabMeta[tab].unread > 99 ? "99+" : tabMeta[tab].unread}
                </span>
              )}
            </button>
          ))}
        </div>
        {items.length === 0 && (
          <div className="text-[11px] text-slate-500 font-mono py-1">
            No recent threats in {tabMeta[activeTab].label} (last {windowDaysByTab[activeTab]} days).
          </div>
        )}
        {items.length > 0 && fallbackByTab[activeTab] && (
          <div className="text-[10px] text-cyber-amber/90 font-mono py-0.5">
            No new 7-day alerts from {tabMeta[activeTab].label}; showing last {windowDaysByTab[activeTab]} days.
          </div>
        )}
        {items.map((it) => (
          <article
            key={it.readKey}
            className="rounded-lg border border-white/10 bg-black/20 px-2.5 py-2.5 hover:border-cyber-amber/30 transition"
          >
            <div className="flex items-start gap-2">
              <span
                className="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0"
                style={{ background: SEVERITY_COLORS[it.severity] }}
              />
              <div className="min-w-0 flex-1">
                <div className="flex items-start gap-2">
                  <a
                    href={it.link}
                    target="_blank"
                    rel="noreferrer"
                    onClick={() => markRead(it.readKey)}
                    className="text-[12px] leading-5 text-slate-200 hover:text-white block flex-1 min-w-0"
                  >
                    {it.title}
                  </a>
                  {!readIds.includes(it.readKey) && (
                    <span className="shrink-0 px-1.5 h-4 rounded-full border border-cyber-cyan/40 bg-cyber-cyan/10 text-cyber-cyan text-[9px] font-mono font-bold flex items-center justify-center uppercase tracking-widest">
                      New
                    </span>
                  )}
                </div>
                {it.description && (
                  <p className="text-[11px] text-slate-400 line-clamp-2 mt-1 leading-relaxed">
                    {it.description}
                  </p>
                )}
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                  <span className="text-slate-500">{timeAgo(it.published)}</span>
                  <span className="text-slate-600">•</span>
                  {it.cveText === "NO-CVE-YET" ? (
                    <span className="text-cyber-amber">NO-CVE-YET</span>
                  ) : (
                    <span className="text-cyber-cyan">{it.cveText}</span>
                  )}
                  <span className="text-slate-600">•</span>
                  <span style={{ color: SEVERITY_COLORS[it.severity] }}>{it.severity}</span>
                  {it.likelyLinux && it.source === "OSS-SEC" && (
                    <>
                      <span className="text-slate-600">•</span>
                      <span className="text-cyber-green">LINUX-SERVICE</span>
                    </>
                  )}
                  <a
                    href={it.link}
                    target="_blank"
                    rel="noreferrer"
                    onClick={() => markRead(it.readKey)}
                    className="ml-auto inline-flex items-center gap-1 text-cyber-cyan hover:text-cyber-cyan/80"
                    title={`Open ${tabMeta[activeTab].label} alert`}
                  >
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            </div>
          </article>
        ))}
      </div>
      </Panel>
      <div
        className="absolute right-0 top-0 h-full w-2 cursor-ew-resize"
        onMouseDown={startResize("right")}
        title="Drag to resize width"
      />
      <div
        className="absolute bottom-0 left-0 h-2 w-full cursor-ns-resize"
        onMouseDown={startResize("bottom")}
        title="Drag to resize height"
      />
      <div
        className="absolute bottom-0 right-0 h-4 w-4 cursor-nwse-resize bg-cyber-amber/20 border-l border-t border-cyber-amber/30"
        onMouseDown={startResize("corner")}
        title="Drag to resize panel"
      />
    </div>
  );
}
