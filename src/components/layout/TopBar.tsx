import {
  Search,
  Bell,
  Sun,
  Moon,
  RefreshCw,
  Activity,
  ShieldAlert,
  Github,
  Bug,
  Radio,
  Crosshair,
  Flame,
  Loader2,
  X,
  AlertTriangle,
  CheckCheck,
  LogOut,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useStore } from "@/lib/store";
import { searchRemote } from "@/lib/api";
import type { CVERecord } from "@/lib/types";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn, timeAgo } from "@/lib/utils";
import { getSession, logout, sessionExpiresIn } from "@/lib/auth";

const NOTIF_META: Record<
  import("@/lib/store").NotificationKind,
  { icon: typeof Bell; tone: string }
> = {
  kev: {
    icon: Bug,
    tone: "border-cyber-red/40 bg-cyber-red/10 text-cyber-red",
  },
  itw: {
    icon: Radio,
    tone: "border-cyber-amber/40 bg-cyber-amber/10 text-cyber-amber",
  },
  "zero-day": {
    icon: Flame,
    tone: "border-cyber-red/40 bg-cyber-red/10 text-cyber-red",
  },
  critical: {
    icon: ShieldAlert,
    tone: "border-cyber-amber/40 bg-cyber-amber/10 text-cyber-amber",
  },
  poc: {
    icon: Github,
    tone: "border-cyber-purple/40 bg-cyber-purple/10 text-cyber-purple",
  },
  system: {
    icon: AlertTriangle,
    tone: "border-cyber-cyan/40 bg-cyber-cyan/10 text-cyber-cyan",
  },
};

export default function TopBar() {
  const navigate = useNavigate();
  const refresh = useStore((s) => s.refresh);
  const loading = useStore((s) => s.loading);
  const lastUpdated = useStore((s) => s.lastUpdated);
  const nextRefreshAt = useStore((s) => s.nextRefreshAt);
  const records = useStore((s) => s.records);
  const openCve = useStore((s) => s.openCve);
  const theme = useStore((s) => s.theme);
  const toggleTheme = useStore((s) => s.toggleTheme);
  const notifications = useStore((s) => s.notifications);
  const unreadCount = useStore((s) => s.unreadCount);
  const markAllRead = useStore((s) => s.markAllRead);
  const markNotificationRead = useStore((s) => s.markNotificationRead);
  const clearNotifications = useStore((s) => s.clearNotifications);
  // subscribe to per-second tick so the countdown actually re-renders
  useStore((s) => s.tick);

  const session = getSession();
  const username = session?.username ?? "analyst";
  const initials = username.slice(0, 2).toUpperCase();

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  const [query, setQuery] = useState("");
  const [results, setResults] = useState<CVERecord[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchErr, setSearchErr] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Notifications dropdown
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifTab, setNotifTab] = useState<"new" | "update">("new");
  const notifRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!notifOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (!notifRef.current?.contains(e.target as Node)) setNotifOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [notifOpen]);
  // When dropdown opens, mark everything as read after a short delay so the
  // user can still see which entries were new.
  useEffect(() => {
    if (!notifOpen || unreadCount === 0) return;
    const t = window.setTimeout(() => markAllRead(), 1200);
    return () => window.clearTimeout(t);
  }, [notifOpen, unreadCount, markAllRead]);

  // Debounced live search against /api/search
  useEffect(() => {
    const q = query.trim();
    if (q.length < 2) {
      setResults(null);
      setSearchErr(null);
      setSearching(false);
      return;
    }
    setSearching(true);
    setSearchErr(null);
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const t = window.setTimeout(async () => {
      try {
        const { records: rs } = await searchRemote(q, 12, ctrl.signal);
        if (ctrl.signal.aborted) return;
        setResults(rs);
        setHighlight(0);
      } catch (e: any) {
        if (e?.name === "AbortError") return;
        setSearchErr(String(e?.message ?? e));
        setResults([]);
      } finally {
        if (!ctrl.signal.aborted) setSearching(false);
      }
    }, 350);
    return () => {
      window.clearTimeout(t);
      ctrl.abort();
    };
  }, [query]);

  // Close dropdown on outside click
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const onPick = (r: CVERecord) => {
    openCve(r);
    setOpen(false);
  };

  const critical = records.filter((r) => r.severity === "CRITICAL").length;
  const high = records.filter((r) => r.severity === "HIGH").length;
  const threatLevel =
    critical > 30
      ? { label: "SEVERE", color: "text-cyber-red", ring: "shadow-glowRed" }
      : critical > 10
        ? { label: "ELEVATED", color: "text-cyber-amber", ring: "shadow-glow" }
        : { label: "GUARDED", color: "text-cyber-green", ring: "shadow-glow" };

  const secondsLeft = nextRefreshAt
    ? Math.max(0, Math.floor((nextRefreshAt - Date.now()) / 1000))
    : 0;

  return (
    <header className="sticky top-0 z-40 backdrop-blur-xl bg-bg/70 border-b border-white/5">
      <div className="h-16 px-4 md:px-6 flex items-center gap-4">
        {/* Search */}
        <div className="flex-1 max-w-2xl relative" ref={wrapRef}>
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(true);
            }}
            onFocus={() => query.trim().length >= 2 && setOpen(true)}
            onKeyDown={(e) => {
              if (!results || results.length === 0) return;
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setHighlight((h) => Math.min(results.length - 1, h + 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setHighlight((h) => Math.max(0, h - 1));
              } else if (e.key === "Enter") {
                e.preventDefault();
                onPick(results[highlight]);
              } else if (e.key === "Escape") {
                setOpen(false);
              }
            }}
            placeholder="Search CVE-ID, vendor, product, IOC, technique… (live · NVD + KEV + PoCs)"
            className="w-full h-10 pl-10 pr-20 rounded-xl bg-bg-elev/60 border border-white/5 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan/40 focus:shadow-glow transition"
          />
          <kbd className="hidden md:inline-flex absolute right-3 top-1/2 -translate-y-1/2 items-center gap-1 px-2 py-0.5 rounded-md bg-white/5 border border-white/10 text-[10px] font-mono text-slate-400">
            {searching ? (
              <Loader2 className="w-3 h-3 animate-spin text-cyber-cyan" />
            ) : (
              "⌘ K"
            )}
          </kbd>

          {open && query.trim().length >= 2 && (
            <div className="absolute left-0 right-0 top-full mt-2 rounded-xl border border-white/10 bg-bg-panel/95 backdrop-blur-xl shadow-2xl z-40 overflow-hidden">
              <div className="px-3 py-2 text-[10px] uppercase tracking-widest text-slate-500 font-mono flex items-center justify-between border-b border-white/5">
                <span>
                  {searching
                    ? "searching…"
                    : results
                      ? `${results.length} result${results.length === 1 ? "" : "s"} · live from NVD + PoC indexes`
                      : "type to search"}
                </span>
                {searchErr && (
                  <span className="text-cyber-amber">⚠ {searchErr}</span>
                )}
              </div>
              <ul className="max-h-[28rem] overflow-y-auto">
                {!searching && results && results.length === 0 && (
                  <li className="px-4 py-6 text-center text-slate-500 font-mono text-[12px]">
                    No CVE matches "{query.trim()}". For CVE-IDs, the backend
                    queries NVD + nomi-sec + trickest directly.
                  </li>
                )}
                {results?.map((r, i) => (
                  <li
                    key={`${r.source}-${r.id}`}
                    onMouseEnter={() => setHighlight(i)}
                    onClick={() => onPick(r)}
                    className={cn(
                      "px-3 py-2.5 cursor-pointer border-b border-white/5 last:border-0 transition",
                      i === highlight
                        ? "bg-cyber-cyan/10"
                        : "hover:bg-white/[0.03]"
                    )}
                  >
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-[12.5px] text-white">
                        {r.id}
                      </span>
                      <SeverityBadge severity={r.severity} />
                      {r.cvss != null && (
                        <span className="text-[10px] font-mono text-slate-400">
                          CVSS {r.cvss.toFixed(1)}
                        </span>
                      )}
                      {r.epss != null && (
                        <span className="text-[10px] font-mono text-cyber-purple">
                          EPSS {(r.epss * 100).toFixed(0)}%
                        </span>
                      )}
                      {r.isZeroDay && (
                        <span className="chip border-cyber-red/50 text-cyber-red bg-cyber-red/15 font-mono">
                          <Flame className="w-3 h-3" /> 0-DAY
                        </span>
                      )}
                      {r.exploited && (
                        <span className="chip border-cyber-red/40 text-cyber-red bg-cyber-red/10 font-mono">
                          <Bug className="w-3 h-3" /> KEV
                        </span>
                      )}
                      {(r.pocs?.length ?? 0) > 0 && (
                        <span className="chip border-cyber-purple/40 text-cyber-purple bg-cyber-purple/10 font-mono">
                          <Github className="w-3 h-3" /> {r.pocs?.length}
                        </span>
                      )}
                      {(r.nucleiTemplates?.length ?? 0) > 0 && (
                        <span className="chip border-cyber-cyan/40 text-cyber-cyan bg-cyber-cyan/10 font-mono">
                          <Crosshair className="w-3 h-3" /> {r.nucleiTemplates?.length}
                        </span>
                      )}
                      {(r.inTheWild?.length ?? 0) > 0 && (
                        <span className="chip border-cyber-amber/40 text-cyber-amber bg-cyber-amber/10 font-mono">
                          <Radio className="w-3 h-3" /> ITW
                        </span>
                      )}
                      <span className="ml-auto text-[10px] font-mono text-slate-500">
                        {r.source} · {timeAgo(r.modified)}
                      </span>
                    </div>
                    {r.description && (
                      <p className="text-[11.5px] text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                        {r.description}
                      </p>
                    )}
                    {(r.vendor || r.product) && (
                      <p className="text-[10px] font-mono text-slate-500 mt-0.5">
                        {r.vendor ?? "—"} / {r.product ?? "—"}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Threat level */}
        <div
          className={cn(
            "hidden md:flex items-center gap-2 px-3 h-10 rounded-xl bg-bg-elev/60 border border-white/5",
            threatLevel.ring
          )}
        >
          <ShieldAlert className={cn("w-4 h-4", threatLevel.color)} />
          <div className="leading-tight">
            <div className="text-[10px] uppercase tracking-widest text-slate-500 font-mono">
              Threat Level
            </div>
            <div
              className={cn(
                "text-xs font-display font-semibold tracking-wider",
                threatLevel.color
              )}
            >
              {threatLevel.label}
            </div>
          </div>
          <div className="ml-2 hidden lg:flex gap-1.5 font-mono text-[10px]">
            <span className="text-cyber-red">{critical}C</span>
            <span className="text-cyber-amber">{high}H</span>
          </div>
        </div>

        {/* Live pulse */}
        <div className="hidden md:flex items-center gap-2 px-3 h-10 rounded-xl bg-bg-elev/60 border border-white/5">
          <div className="relative">
            <span className="block w-2 h-2 rounded-full bg-cyber-green" />
            <span className="absolute inset-0 rounded-full bg-cyber-green/60 animate-pulseRing" />
          </div>
          <Activity className="w-4 h-4 text-cyber-green" />
          <span className="text-[11px] font-mono text-slate-300">
            LIVE · sync in {secondsLeft}s
          </span>
        </div>

        {/* Refresh */}
        <button
          onClick={() => void refresh()}
          className="h-10 px-3 rounded-xl bg-bg-elev/60 border border-white/5 hover:border-cyber-cyan/40 text-slate-300 hover:text-cyber-cyan transition flex items-center gap-2"
          title={
            lastUpdated
              ? `Last updated ${new Date(lastUpdated).toLocaleTimeString()}`
              : "Refresh"
          }
        >
          <RefreshCw
            className={cn("w-4 h-4", loading && "animate-spin text-cyber-cyan")}
          />
          <span className="hidden lg:inline text-[11px] font-mono">SYNC</span>
        </button>

        {/* Bell */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => setNotifOpen((v) => !v)}
            className={cn(
              "relative h-10 w-10 rounded-xl bg-bg-elev/60 border border-white/5 transition flex items-center justify-center",
              notifOpen
                ? "border-cyber-purple/50 text-cyber-purple"
                : "hover:border-cyber-purple/40 hover:text-cyber-purple text-slate-300"
            )}
            title={
              unreadCount
                ? `${unreadCount} new notification${unreadCount === 1 ? "" : "s"}`
                : "Notifications"
            }
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 min-w-[18px] h-[18px] px-1 rounded-full bg-cyber-red text-white text-[10px] font-mono font-bold flex items-center justify-center ring-2 ring-bg">
                {unreadCount > 99 ? "99+" : unreadCount}
              </span>
            )}
          </button>
          {notifOpen && (
            <div
              className="absolute right-0 top-full mt-2 w-[380px] max-h-[70vh] rounded-xl border border-white/10 shadow-2xl z-[100] overflow-hidden flex flex-col"
              style={{ backgroundColor: "#121826" }}
            >
              <div className="px-3 py-2 border-b border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Bell className="w-3.5 h-3.5 text-cyber-purple" />
                  <span className="text-[11px] uppercase tracking-widest font-mono text-slate-400">
                    Notifications
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">
                    {notifications.length}
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  {notifications.length > 0 && (
                    <>
                      <button
                        onClick={() => markAllRead()}
                        className="text-[10px] text-slate-400 hover:text-cyber-cyan flex items-center gap-1"
                        title="Mark all read"
                      >
                        <CheckCheck className="w-3 h-3" /> read
                      </button>
                      <button
                        onClick={() => clearNotifications()}
                        className="text-[10px] text-slate-400 hover:text-cyber-red flex items-center gap-1"
                        title="Clear all"
                      >
                        <X className="w-3 h-3" /> clear
                      </button>
                    </>
                  )}
                </div>
              </div>
              {/* Tabs */}
              {(() => {
                const newItems = notifications.filter(
                  (n) => n.category === "new"
                );
                const updItems = notifications.filter(
                  (n) => n.category === "update"
                );
                const newUnread = newItems.filter((n) => !n.read).length;
                const updUnread = updItems.filter((n) => !n.read).length;
                const list = notifTab === "new" ? newItems : updItems;
                return (
                  <>
                    <div className="flex border-b border-white/5 bg-bg-elev/40">
                      <button
                        onClick={() => setNotifTab("new")}
                        className={cn(
                          "flex-1 px-3 py-2 text-[11px] font-mono uppercase tracking-widest transition flex items-center justify-center gap-1.5 border-b-2",
                          notifTab === "new"
                            ? "text-cyber-cyan border-cyber-cyan"
                            : "text-slate-400 border-transparent hover:text-slate-200"
                        )}
                      >
                        <ShieldAlert className="w-3 h-3" />
                        New
                        <span className="text-[10px] text-slate-500">
                          {newItems.length}
                        </span>
                        {newUnread > 0 && (
                          <span className="ml-0.5 min-w-[14px] h-[14px] px-1 rounded-full bg-cyber-red text-white text-[9px] font-bold flex items-center justify-center">
                            {newUnread > 99 ? "99+" : newUnread}
                          </span>
                        )}
                      </button>
                      <button
                        onClick={() => setNotifTab("update")}
                        className={cn(
                          "flex-1 px-3 py-2 text-[11px] font-mono uppercase tracking-widest transition flex items-center justify-center gap-1.5 border-b-2",
                          notifTab === "update"
                            ? "text-cyber-purple border-cyber-purple"
                            : "text-slate-400 border-transparent hover:text-slate-200"
                        )}
                      >
                        <RefreshCw className="w-3 h-3" />
                        Updates
                        <span className="text-[10px] text-slate-500">
                          {updItems.length}
                        </span>
                        {updUnread > 0 && (
                          <span className="ml-0.5 min-w-[14px] h-[14px] px-1 rounded-full bg-cyber-red text-white text-[9px] font-bold flex items-center justify-center">
                            {updUnread > 99 ? "99+" : updUnread}
                          </span>
                        )}
                      </button>
                    </div>
                    <ul className="overflow-y-auto overscroll-contain divide-y divide-white/5">
                      {list.length === 0 && (
                        <li className="px-4 py-6 text-center text-[12px] font-mono text-slate-500 space-y-2">
                          <div>
                            {notifTab === "new"
                              ? "Nothing new since you opened this tab."
                              : "No updates since you opened this tab."}
                          </div>
                          <div className="text-[10.5px] text-slate-600 leading-relaxed">
                            {notifTab === "new"
                              ? "Tracks brand-new CVE IDs that arrive in successive refreshes."
                              : "Tracks changes to existing CVEs — new PoCs, KEV/ITW additions, CVSS re-scoring."}
                          </div>
                          {lastUpdated && (
                            <div className="text-[10px] text-slate-600 pt-1 border-t border-white/5">
                              Feed last refreshed{" "}
                              <span className="text-slate-400">
                                {new Date(lastUpdated).toLocaleTimeString()}
                              </span>
                              {" · auto every 3 min"}
                            </div>
                          )}
                        </li>
                      )}
                      {list.map((n) => {
                        const meta = NOTIF_META[n.kind];
                        const Icon = meta.icon;
                        return (
                          <li
                            key={n.id}
                            onClick={() => {
                              markNotificationRead(n.id);
                              if (n.cveId) {
                                const rec = records.find(
                                  (r) => r.id === n.cveId
                                );
                                if (rec) {
                                  openCve(rec);
                                  setNotifOpen(false);
                                }
                              }
                            }}
                            className={cn(
                              "px-3 py-2.5 transition flex items-start gap-2.5",
                              n.cveId && "cursor-pointer hover:bg-white/[0.04]",
                              !n.read && "bg-cyber-cyan/[0.04]"
                            )}
                          >
                            <span
                              className={cn(
                                "shrink-0 w-7 h-7 rounded-lg border flex items-center justify-center",
                                meta.tone
                              )}
                            >
                              <Icon className="w-3.5 h-3.5" />
                            </span>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-[12px] text-white font-medium truncate">
                                  {n.title}
                                </span>
                                {!n.read && (
                                  <>
                                    <span className="shrink-0 px-1.5 h-4 rounded-full border border-cyber-cyan/40 bg-cyber-cyan/10 text-cyber-cyan text-[9px] font-mono font-bold flex items-center justify-center uppercase tracking-widest">
                                      New
                                    </span>
                                    <span className="shrink-0 w-1.5 h-1.5 rounded-full bg-cyber-cyan" />
                                  </>
                                )}
                              </div>
                              {n.detail && (
                                <div className="text-[11px] text-slate-400 font-mono truncate">
                                  {n.detail}
                                </div>
                              )}
                              <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                                {timeAgo(new Date(n.ts).toISOString())}
                              </div>
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  </>
                );
              })()}
            </div>
          )}
        </div>

        {/* Theme */}
        <button
          onClick={() => toggleTheme()}
          className="h-10 w-10 rounded-xl bg-bg-elev/60 border border-white/5 hover:border-cyber-cyan/40 text-slate-300 transition flex items-center justify-center"
          title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
        >
          {theme === "dark" ? (
            <Sun className="w-4 h-4" />
          ) : (
            <Moon className="w-4 h-4" />
          )}
        </button>

        {/* Profile */}
        <div className="h-10 pl-1 pr-3 rounded-xl bg-bg-elev/60 border border-white/5 flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyber-cyan to-cyber-purple flex items-center justify-center text-bg font-display font-bold text-sm">
            {initials}
          </div>
          <div className="hidden md:block leading-tight">
            <div className="text-xs text-white font-medium">{username}</div>
            <div className="text-[10px] text-slate-500 font-mono">
              session · {sessionExpiresIn()} left
            </div>
          </div>
        </div>

        {/* Logout */}
        <button
          onClick={handleLogout}
          className="h-10 w-10 rounded-xl bg-bg-elev/60 border border-white/5 hover:border-cyber-red/40 text-slate-400 hover:text-cyber-red transition flex items-center justify-center"
          title="Sign out"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
}
