import { create } from "zustand";
import type {
  CVERecord,
  FeedCounts,
  OssMailingSignal,
  ThreatFeedItem,
} from "./types";
import { fetchAllSources } from "./api";

export type NotificationKind =
  | "kev"
  | "itw"
  | "zero-day"
  | "critical"
  | "poc"
  | "system";

export type NotificationCategory = "new" | "update";

export interface Notification {
  id: string;            // unique id (cve + kind + seq)
  kind: NotificationKind;
  category: NotificationCategory;
  cveId?: string;
  title: string;
  detail?: string;
  ts: number;            // epoch ms
  read: boolean;
  severity?: CVERecord["severity"];
}

interface State {
  records: CVERecord[];
  loading: boolean;
  error: string | null;
  errors: string[];
  lastUpdated: string | null;
  nextRefreshAt: number | null;
  feed: ThreatFeedItem[];
  ossMailing: OssMailingSignal[];
  backendOnline: boolean;
  feedBuilding: boolean;
  counts: FeedCounts | null;
  tick: number;
  focusedCve: CVERecord | null;

  // Notifications
  notifications: Notification[];
  unreadCount: number;
  markAllRead: () => void;
  markNotificationRead: (id: string) => void;
  clearNotifications: () => void;

  // Theme
  theme: "dark" | "light";
  setTheme: (t: "dark" | "light") => void;
  toggleTheme: () => void;

  refresh: () => Promise<void>;
  startAutoRefresh: () => void;
  stopAutoRefresh: () => void;
  openCve: (r: CVERecord) => void;
  closeCve: () => void;
}

const REFRESH_MS = 3 * 60 * 1000; // 3 minutes
const MAX_NOTIFS = 80;

let intervalId: number | null = null;
let tickId: number | null = null;
let buildPollId: ReturnType<typeof setTimeout> | null = null;
let isRefreshing = false;
// Per-CVE signature snapshot from the previous refresh. Lets us distinguish
// brand-new CVEs (id absent) from existing ones whose metadata changed
// (signature differs) so the notification panel can show a 'New' vs an
// 'Updates' stream.
interface CveSig {
  modified: string | null;
  pocs: number;
  kev: boolean;
  itw: boolean;
  zeroDay: boolean;
  cvss: number;
  severity: CVERecord["severity"] | null;
}
const seenCves = new Map<string, CveSig>();
const seenSystem = new Set<string>();

function sigOf(r: CVERecord): CveSig {
  return {
    modified: r.modified ?? null,
    pocs: r.pocs?.length ?? 0,
    kev: !!r.exploited,
    itw: !!r.inTheWild?.some((e) => e?.confirmed === true),
    zeroDay: !!r.isZeroDay,
    cvss: r.cvss ?? 0,
    severity: r.severity ?? null,
  };
}

function pickKindForNew(s: CveSig): NotificationKind {
  if (s.zeroDay) return "zero-day";
  if (s.kev) return "kev";
  if (s.itw) return "itw";
  if (s.severity === "CRITICAL" && s.cvss >= 9) return "critical";
  if (s.pocs > 0) return "poc";
  return "critical";
}

function loadInitialTheme(): "dark" | "light" {
  if (typeof window === "undefined") return "dark";
  const saved = localStorage.getItem("zsg-theme");
  if (saved === "light" || saved === "dark") return saved;
  return "dark";
}

function applyTheme(t: "dark" | "light") {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = t;
  document.documentElement.style.colorScheme = t;
  try {
    localStorage.setItem("zsg-theme", t);
  } catch {
    /* ignore */
  }
}

function deriveNotifications(
  records: CVERecord[],
  isFirstLoad: boolean
): Notification[] {
  const now = Date.now();
  const out: Notification[] = [];

  // First load: just snapshot, no notifications (avoid dumping the entire
  // historical backlog into the panel).
  if (isFirstLoad) {
    for (const r of records) seenCves.set(r.id, sigOf(r));
    return [];
  }

  for (const r of records) {
    const next = sigOf(r);
    const prev = seenCves.get(r.id);
    seenCves.set(r.id, next);

    // --- NEW: first time we observe this CVE id ---
    if (!prev) {
      // "First-seen" by this browser session != "newly published". CVEs that
      // are days/years old can land in the feed because of backfill or the
      // rolling time window — those belong on the Updates tab, not New.
      const publishedAt = new Date(r.published ?? 0).getTime();
      const NEW_WINDOW_MS = 48 * 3600_000; // 48h
      const trulyNew =
        Number.isFinite(publishedAt) &&
        publishedAt > 0 &&
        now - publishedAt <= NEW_WINDOW_MS;

      if (trulyNew) {
        const kind = pickKindForNew(next);
        const headlineByKind: Record<NotificationKind, string> = {
          "zero-day": `0-day grade CVE published: ${r.id}`,
          kev: `New KEV-listed CVE: ${r.id}`,
          itw: `New in-the-wild CVE: ${r.id}`,
          critical: `Critical CVE published: ${r.id}`,
          poc: `New CVE with public PoC: ${r.id}`,
          system: `New CVE published: ${r.id}`,
        };
        out.push({
          id: `new:${r.id}:${now}`,
          kind,
          category: "new",
          cveId: r.id,
          title: headlineByKind[kind],
          detail: `CVSS ${next.cvss ? next.cvss.toFixed(1) : "—"} · ${r.vendor ?? ""} ${r.product ?? ""}`.trim(),
          ts: now,
          read: false,
          severity: r.severity,
        });
      } else {
        // Older CVE that just appeared in the feed — backfill / window scroll.
        out.push({
          id: `idx:${r.id}:${now}`,
          kind: "system",
          category: "update",
          cveId: r.id,
          title: `${r.id} added to feed`,
          detail: `Published ${r.published ? new Date(r.published).toLocaleDateString() : "—"} · ${r.vendor ?? ""} ${r.product ?? ""}`.trim(),
          ts: now,
          read: false,
          severity: r.severity,
        });
      }
      continue;
    }

    // --- UPDATE: existing CVE whose threat metadata changed ---
    if (!prev.kev && next.kev) {
      out.push({
        id: `upd-kev:${r.id}:${now}`,
        kind: "kev",
        category: "update",
        cveId: r.id,
        title: `${r.id} added to CISA KEV`,
        detail: `${r.vendor ?? "unknown"} / ${r.product ?? "—"} — actively exploited`,
        ts: now,
        read: false,
        severity: r.severity,
      });
    }
    if (!prev.itw && next.itw) {
      out.push({
        id: `upd-itw:${r.id}:${now}`,
        kind: "itw",
        category: "update",
        cveId: r.id,
        title: `${r.id} confirmed exploited in the wild`,
        detail: `inthewild.io reported activity`,
        ts: now,
        read: false,
        severity: r.severity,
      });
    }
    if (!prev.zeroDay && next.zeroDay) {
      out.push({
        id: `upd-zd:${r.id}:${now}`,
        kind: "zero-day",
        category: "update",
        cveId: r.id,
        title: `${r.id} reclassified as 0-day grade`,
        detail: `Score ${r.zeroDayScore ?? "?"} · ${r.vendor ?? ""} ${r.product ?? ""}`.trim(),
        ts: now,
        read: false,
        severity: r.severity,
      });
    }
    if (next.pocs > prev.pocs) {
      out.push({
        id: `upd-poc:${r.id}:${now}`,
        kind: "poc",
        category: "update",
        cveId: r.id,
        title: `New public PoC for ${r.id}`,
        detail: `${next.pocs} repo(s) on GitHub (+${next.pocs - prev.pocs})`,
        ts: now,
        read: false,
        severity: r.severity,
      });
    }
    if (Math.abs(next.cvss - prev.cvss) >= 0.5) {
      out.push({
        id: `upd-cvss:${r.id}:${now}`,
        kind: "critical",
        category: "update",
        cveId: r.id,
        title: `${r.id} CVSS updated`,
        detail: `${prev.cvss ? prev.cvss.toFixed(1) : "—"} → ${next.cvss ? next.cvss.toFixed(1) : "—"}`,
        ts: now,
        read: false,
        severity: r.severity,
      });
    }
  }
  // Cap noise per cycle
  return out.slice(0, 40);
}

const initialTheme = loadInitialTheme();
applyTheme(initialTheme);

export const useStore = create<State>((set, get) => ({
  records: [],
  loading: false,
  error: null,
  errors: [],
  lastUpdated: null,
  nextRefreshAt: null,
  feed: [],
  ossMailing: [],
  backendOnline: false,
  feedBuilding: false,
  counts: null,
  tick: 0,
  focusedCve: null,

  notifications: [],
  unreadCount: 0,
  markAllRead() {
    set((s) => ({
      notifications: s.notifications.map((n) => ({ ...n, read: true })),
      unreadCount: 0,
    }));
  },
  markNotificationRead(id) {
    set((s) => {
      let changed = false;
      const notifications = s.notifications.map((n) => {
        if (n.id !== id || n.read) return n;
        changed = true;
        return { ...n, read: true };
      });
      if (!changed) return s;
      return {
        notifications,
        unreadCount: notifications.filter((n) => !n.read).length,
      };
    });
  },
  clearNotifications() {
    set({ notifications: [], unreadCount: 0 });
  },

  theme: initialTheme,
  setTheme(t) {
    applyTheme(t);
    set({ theme: t });
  },
  toggleTheme() {
    const next = get().theme === "dark" ? "light" : "dark";
    applyTheme(next);
    set({ theme: next });
  },

  async refresh() {
    // Guard: skip if another refresh is already in flight.
    if (isRefreshing) return;
    isRefreshing = true;
    set({ loading: true, error: null });
    try {
      const { records, ossMailing, errors, fetchedAt, counts, backendOnline, building } =
        await fetchAllSources();
      const isBuilding = backendOnline && (building ?? false);
      const feed: ThreatFeedItem[] = records.slice(0, 30).map((r) => ({
        id: r.id,
        ts: r.modified,
        title: `${r.id} — ${r.description?.slice(0, 90) ?? ""}`,
        severity: r.severity,
        source: r.source,
      }));
      const wasFirstLoad = get().records.length === 0;
      const newNotifs = deriveNotifications(records, wasFirstLoad);
      // Surface a 'system' note when source errors change
      const sysNotes: Notification[] = [];
      if (errors.length > 0) {
        const errKey = `sys:${errors.join("|")}`;
        if (!seenSystem.has(errKey)) {
          seenSystem.add(errKey);
          sysNotes.push({
            id: errKey,
            kind: "system",
            category: "update",
            title: `${errors.length} source(s) degraded`,
            detail: errors.join(" · "),
            ts: Date.now(),
            read: false,
          });
        }
      }
      const merged = [...sysNotes, ...newNotifs, ...get().notifications].slice(
        0,
        MAX_NOTIFS
      );
      set({
        records,
        feed,
        ossMailing,
        loading: false,
        errors,
        lastUpdated: fetchedAt,
        nextRefreshAt: Date.now() + REFRESH_MS,
        backendOnline,
        feedBuilding: isBuilding,
        counts: counts ?? null,
        notifications: merged,
        unreadCount: merged.filter((n) => !n.read).length,
      });
      // While the feed is still building, poll every 5s with a tracked timer
      // (cancellable) instead of stacking untracked setTimeouts.
      if (buildPollId) clearTimeout(buildPollId);
      buildPollId = isBuilding
        ? setTimeout(() => { buildPollId = null; void get().refresh(); }, 5_000)
        : null;
    } catch (e: any) {
      set({ loading: false, error: e.message ?? String(e) });
    } finally {
      isRefreshing = false;
    }
  },

  startAutoRefresh() {
    if (intervalId) return;
    void get().refresh();
    intervalId = window.setInterval(() => void get().refresh(), REFRESH_MS);
    // ticker so countdown updates each second
    tickId = window.setInterval(() => {
      set((s) => ({ tick: s.tick + 1 }));
    }, 1000);
  },

  stopAutoRefresh() {
    if (intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
    if (tickId) {
      clearInterval(tickId);
      tickId = null;
    }
    if (buildPollId) {
      clearTimeout(buildPollId);
      buildPollId = null;
    }
  },

  openCve(r) {
    // Also inject into records list if missing so the CVE page reflects it.
    set((s) => {
      const exists = s.records.some((x) => x.id === r.id);
      return {
        focusedCve: r,
        records: exists ? s.records : [r, ...s.records],
      };
    });
  },

  closeCve() {
    set({ focusedCve: null });
  },
}));

