import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  Filter,
  ExternalLink,
  X,
  ChevronLeft,
  ChevronRight,
  Bug,
  Linkedin,
  Github,
  Flame,
  Radio,
  Crosshair,
  ArrowUp,
  ArrowDown,
  ChevronsUpDown,
  Columns3,
  Check,
  RefreshCw,
  Sparkles,
} from "lucide-react";
import { useStore } from "@/lib/store";
import { askAiAboutCve, listOllamaModels } from "@/lib/api";
import { SeverityBadge, ScoreBar } from "@/components/ui/SeverityBadge";
import { cn, timeAgo, SEVERITY_COLORS } from "@/lib/utils";
import type { CVERecord, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SOURCES = [
  "NVD",
  "MITRE",
  "OSV",
  "KEV",
  "REDHAT",
  "TENABLE",
  "UBUNTU-USN",
  "OSS-SEC",
  "POC-ONLY",
] as const;
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

type TimeRange = "today" | "yesterday" | "7d" | "1mo" | "2mo";
const TIME_RANGES: { id: TimeRange; label: string }[] = [
  { id: "today", label: "Today" },
  { id: "yesterday", label: "Yesterday" },
  { id: "7d", label: "Last 7 days" },
  { id: "1mo", label: "Last month" },
  { id: "2mo", label: "Last 2 months" },
];

function rangeWindow(range: TimeRange): { start: number; end: number } {
  const now = new Date();
  const todayStart = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate()
  ).getTime();
  const dayMs = 86_400_000;
  switch (range) {
    case "today":
      return { start: todayStart, end: now.getTime() };
    case "yesterday":
      return { start: todayStart - dayMs, end: todayStart };
    case "7d":
      return { start: now.getTime() - 7 * dayMs, end: now.getTime() };
    case "1mo":
      return { start: now.getTime() - 30 * dayMs, end: now.getTime() };
    case "2mo":
      return { start: now.getTime() - 60 * dayMs, end: now.getTime() };
  }
}

type ColId =
  | "cve"
  | "severity"
  | "cvss"
  | "epss"
  | "intel"
  | "vendor"
  | "category"
  | "source"
  | "published"
  | "modified";

const ALL_COLS: { id: ColId; label: string }[] = [
  { id: "cve", label: "CVE" },
  { id: "severity", label: "Severity" },
  { id: "cvss", label: "CVSS" },
  { id: "epss", label: "EPSS" },
  { id: "intel", label: "Exploit Intel" },
  { id: "vendor", label: "Vendor / Product" },
  { id: "category", label: "Category" },
  { id: "source", label: "Source" },
  { id: "published", label: "Published" },
  { id: "modified", label: "Modified" },
];

const SEVERITY_ORDER: Record<Severity, number> = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

function sortValue(r: CVERecord, id: ColId): number | string {
  switch (id) {
    case "cve":
      return r.id;
    case "severity":
      return SEVERITY_ORDER[r.severity] ?? -1;
    case "cvss":
      return r.cvss ?? -1;
    case "epss":
      return r.epss ?? -1;
    case "intel":
      return (
        (r.pocs?.length ?? 0) +
        (r.exploits?.length ?? 0) +
        (r.inTheWild?.length ?? 0) +
        (r.nucleiTemplates?.length ?? 0)
      );
    case "vendor":
      return `${r.vendor ?? ""} ${r.product ?? ""}`.toLowerCase();
    case "category":
      return r.category ?? "";
    case "source":
      return r.source;
    case "published":
      return new Date(r.published).getTime();
    case "modified":
      return new Date(r.modified).getTime();
  }
}

export default function CVEs() {
  const records = useStore((s) => s.records);
  const loading = useStore((s) => s.loading);
  const openCve = useStore((s) => s.openCve);
  const lastUpdated = useStore((s) => s.lastUpdated);
  const refresh = useStore((s) => s.refresh);

  const location = useLocation();
  const navigate = useNavigate();

  const [query, setQuery] = useState("");
  const [sevFilter, setSev] = useState<Set<Severity>>(new Set());
  const [srcFilter, setSrc] = useState<Set<string>>(new Set());
  const [catFilter, setCat] = useState<Set<string>>(new Set());
  const [kevOnly, setKevOnly] = useState(false);
  const [linuxOnly, setLinuxOnly] = useState(false);
  const [pocOnly, setPocOnly] = useState(false);
  const [zeroDayOnly, setZeroDayOnly] = useState(false);
  const [itwOnly, setItwOnly] = useState(false);
  const [nucleiOnly, setNucleiOnly] = useState(false);
  const [page, setPage] = useState(0);

  // Apply incoming URL params (drill-through from dashboard widgets).
  // Recognised: severity, category, source, q, kev, linuxOnly, pocOnly, zeroDay.
  // Once applied the params are stripped so reloads don't keep re-applying.
  useEffect(() => {
    if (!location.search) return;
    const p = new URLSearchParams(location.search);
    let touched = false;
    const sev = p.get("severity");
    if (sev && SEVERITIES.includes(sev as Severity)) {
      setSev(new Set([sev as Severity]));
      touched = true;
    }
    const cat = p.get("category");
    if (cat) {
      setCat(new Set([cat]));
      touched = true;
    }
    const src = p.get("source");
    if (src) {
      setSrc(new Set([src]));
      touched = true;
    }
    const q = p.get("q");
    if (q) {
      setQuery(q);
      touched = true;
    }
    if (p.get("kev") === "1") {
      setKevOnly(true);
      touched = true;
    }
    if (p.get("linuxOnly") === "1") {
      setLinuxOnly(true);
      touched = true;
    }
    if (p.get("pocOnly") === "1") {
      setPocOnly(true);
      touched = true;
    }
    if (p.get("zeroDay") === "1") {
      setZeroDayOnly(true);
      touched = true;
    }
    const range = p.get("range");
    if (range && TIME_RANGES.some((r) => r.id === range)) {
      setTimeRange(range as TimeRange);
      touched = true;
    }
    const basis = p.get("basis");
    if (basis === "modified" || basis === "published") {
      setWindowBasis(basis);
      touched = true;
    }
    if (touched) navigate("/cves", { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Time-range pill (default: last 7 days). Persisted to localStorage.
  const [timeRange, setTimeRange] = useState<TimeRange>(() => {
    try {
      const s = localStorage.getItem("sg-time-range") as TimeRange | null;
      if (s && TIME_RANGES.some((r) => r.id === s)) return s;
    } catch {}
    return "7d";
  });
  useEffect(() => {
    try {
      localStorage.setItem("sg-time-range", timeRange);
    } catch {}
  }, [timeRange]);

  // Which date field the window applies to (modified vs published).
  const [windowBasis, setWindowBasis] = useState<"modified" | "published">(
    () => {
      try {
        const s = localStorage.getItem("sg-window-basis");
        if (s === "modified" || s === "published") return s;
      } catch {}
      return "modified";
    }
  );
  useEffect(() => {
    try {
      localStorage.setItem("sg-window-basis", windowBasis);
    } catch {}
  }, [windowBasis]);

  // Sort: default Modified desc (newest first)
  const [sort, setSort] = useState<{ key: ColId; dir: "asc" | "desc" }>(() => {
    try {
      const s = localStorage.getItem("sg-sort");
      if (s) return JSON.parse(s);
    } catch {}
    return { key: "modified", dir: "desc" };
  });
  useEffect(() => {
    try {
      localStorage.setItem("sg-sort", JSON.stringify(sort));
    } catch {}
  }, [sort]);

  // Column visibility (persisted)
  const [visibleCols, setVisibleCols] = useState<Set<ColId>>(() => {
    try {
      const s = localStorage.getItem("sg-visible-cols");
      if (s) return new Set(JSON.parse(s) as ColId[]);
    } catch {}
    return new Set(ALL_COLS.map((c) => c.id));
  });
  useEffect(() => {
    try {
      localStorage.setItem(
        "sg-visible-cols",
        JSON.stringify([...visibleCols])
      );
    } catch {}
  }, [visibleCols]);
  const [colMenuOpen, setColMenuOpen] = useState(false);
  const colMenuRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!colMenuOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (!colMenuRef.current?.contains(e.target as Node))
        setColMenuOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [colMenuOpen]);
  const toggleCol = (id: ColId) => {
    setVisibleCols((prev) => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      if (n.size === 0) n.add("cve"); // never allow empty
      return n;
    });
  };

  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim();
    const { start, end } = rangeWindow(timeRange);
    return records.filter((r) => {
      const basisRaw = windowBasis === "published" ? r.published : r.modified;
      const t = new Date(basisRaw ?? r.modified).getTime();
      if (Number.isFinite(t) && (t < start || t > end)) return false;
      if (sevFilter.size && !sevFilter.has(r.severity)) return false;
      if (srcFilter.size && !srcFilter.has(r.source)) return false;
      if (catFilter.size && !catFilter.has(r.category ?? "general"))
        return false;
      if (kevOnly && !r.exploited) return false;
      if (pocOnly && !(r.pocs && r.pocs.length > 0)) return false;
      if (zeroDayOnly && !r.isZeroDay) return false;
      if (itwOnly && !(r.inTheWild && r.inTheWild.length > 0)) return false;
      if (nucleiOnly && !(r.nucleiTemplates && r.nucleiTemplates.length > 0)) return false;
      if (
        linuxOnly &&
        !["linux-kernel", "linux-service", "container"].includes(r.category ?? "")
      )
        return false;
      if (q) {
        const hay = `${r.id} ${r.description} ${r.vendor ?? ""} ${r.product ?? ""} ${(r.tags ?? []).join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [records, query, timeRange, windowBasis, sevFilter, srcFilter, catFilter, kevOnly, linuxOnly, pocOnly, zeroDayOnly, itwOnly, nucleiOnly]);

  // Date of the freshest CVE we have, by the current basis — used to explain
  // empty-state when "Published / Today" returns nothing on weekends/holidays.
  const latestPublishedStr = useMemo(() => {
    let maxMs = 0;
    for (const r of records) {
      const v = windowBasis === "published" ? r.published : r.modified;
      const t = new Date(v ?? 0).getTime();
      if (Number.isFinite(t) && t > maxMs) maxMs = t;
    }
    return maxMs > 0 ? `${timeAgo(new Date(maxMs).toISOString())} (${new Date(maxMs).toLocaleString()})` : null;
  }, [records, windowBasis]);

  const PAGE_SIZE = 25;
  const sorted = useMemo(() => {
    const arr = [...filtered];
    const { key, dir } = sort;
    arr.sort((a, b) => {
      const va = sortValue(a, key);
      const vb = sortValue(b, key);
      if (va < vb) return dir === "asc" ? -1 : 1;
      if (va > vb) return dir === "asc" ? 1 : -1;
      return 0;
    });
    return arr;
  }, [filtered, sort]);
  const pageCount = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const rows = sorted.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

  const onSort = (id: ColId) => {
    setSort((prev) =>
      prev.key === id
        ? { key: id, dir: prev.dir === "asc" ? "desc" : "asc" }
        : { key: id, dir: id === "published" || id === "modified" ? "desc" : "asc" }
    );
    setPage(0);
  };

  const toggle = <T,>(set: Set<T>, v: T, setter: (s: Set<T>) => void) => {
    const n = new Set(set);
    n.has(v) ? n.delete(v) : n.add(v);
    setter(n);
    setPage(0);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-end justify-between flex-wrap gap-3">
        <div>
          <h1 className="font-display text-2xl font-semibold text-white tracking-wide">
            Vulnerability Intelligence
          </h1>
          <p className="text-[12px] text-slate-500 font-mono">
            {filtered.length.toLocaleString()} of {records.length.toLocaleString()} records
            · auto-syncing every 3 minutes
          </p>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono flex-wrap">
          <span className="chip border-cyber-cyan/30 text-cyber-cyan bg-cyber-cyan/10">
            NVD
          </span>
          <span className="chip border-cyber-purple/30 text-cyber-purple bg-cyber-purple/10">
            OSV
          </span>
          <span className="chip border-cyber-red/30 text-cyber-red bg-cyber-red/10">
            CISA KEV
          </span>
          <span className="chip border-cyber-purple/30 text-cyber-purple bg-cyber-purple/10">
            GitHub PoCs
          </span>
          <span className="chip border-cyber-purple/30 text-cyber-purple bg-cyber-purple/10">
            trickest/cve
          </span>
          <span className="chip border-cyber-amber/30 text-cyber-amber bg-cyber-amber/10">
            Exploit-DB
          </span>
          <span className="chip border-cyber-cyan/30 text-cyber-cyan bg-cyber-cyan/10">
            Nuclei templates
          </span>
          <span className="chip border-cyber-red/30 text-cyber-red bg-cyber-red/10">
            Nuclei ITW
          </span>
          <span className="chip border-cyber-green/30 text-cyber-green bg-cyber-green/10">
            FIRST EPSS
          </span>
        </div>
      </div>

      {/* Filter bar */}
      <div className="glass p-3 space-y-3 relative z-30">
        {/* Time range pills */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          {/* Left group: window label + basis toggle + range pills */}
          <div className="flex items-center gap-2 flex-wrap min-w-0">
            <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-slate-500 font-mono pr-2 border-r border-white/5">
              <Filter className="w-3 h-3" /> Window
            </div>
            {/* Basis toggle (modified vs published) */}
            <div className="inline-flex rounded-full border border-white/10 overflow-hidden text-[10px] font-mono uppercase tracking-wider shrink-0">
              {(["modified", "published"] as const).map((b) => (
                <button
                  key={b}
                  onClick={() => {
                    setWindowBasis(b);
                    setPage(0);
                  }}
                  className={cn(
                    "px-2.5 h-7 transition",
                    windowBasis === b
                      ? "bg-cyber-cyan/15 text-cyber-cyan"
                      : "text-slate-400 hover:text-white"
                  )}
                  title={
                    b === "modified"
                      ? "Filter by last modified date (record changed recently)"
                      : "Filter by NVD/MITRE publish date (new disclosure)"
                  }
                >
                  {b}
                </button>
              ))}
            </div>
            {TIME_RANGES.map((r) => {
              const active = timeRange === r.id;
              return (
                <button
                  key={r.id}
                  onClick={() => {
                    setTimeRange(r.id);
                    setPage(0);
                  }}
                  className={cn(
                    "h-7 px-2.5 rounded-full border text-[10px] font-mono uppercase tracking-wider transition shrink-0",
                    active
                      ? "border-cyber-cyan/50 text-cyber-cyan bg-cyber-cyan/10 shadow-glow"
                      : "border-white/10 text-slate-400 hover:text-white hover:border-white/20"
                  )}
                >
                  {r.label}
                </button>
              );
            })}
          </div>
          {/* Right group: quick actions */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => {
                setWindowBasis("published");
                setTimeRange("today");
                setPage(0);
              }}
              title="Jump to: CVEs published today (NVD + MITRE + OSV + KEV)"
              className={cn(
                "inline-flex items-center gap-1 px-2.5 h-7 rounded-full border text-[10px] uppercase tracking-wider font-mono transition",
                windowBasis === "published" && timeRange === "today"
                  ? "border-cyber-amber/60 text-cyber-amber bg-cyber-amber/10 shadow-glow"
                  : "border-cyber-amber/30 text-cyber-amber/80 hover:bg-cyber-amber/10 hover:text-cyber-amber"
              )}
            >
              <Sparkles className="w-3 h-3" /> New today
            </button>
            <button
              type="button"
              onClick={() => void refresh()}
              disabled={loading}
              title={
                lastUpdated
                  ? `Last refreshed ${new Date(lastUpdated).toLocaleTimeString()} · backend retains 60d · click to pull fresh data`
                  : "Refresh feed"
              }
              className="inline-flex items-center gap-1 px-2.5 h-7 rounded-full border border-white/10 hover:border-cyber-cyan/40 hover:text-cyber-cyan text-slate-400 disabled:opacity-50 transition text-[10px] uppercase tracking-wider font-mono"
            >
              <RefreshCw className={cn("w-3 h-3", loading && "animate-spin")} />
              {lastUpdated ? timeAgo(lastUpdated) : "refresh"}
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(0);
              }}
              placeholder="Search CVE-ID, vendor, product, description…"
              className="w-full h-9 pl-10 pr-3 rounded-lg bg-bg-elev/60 border border-white/5 text-[13px] text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan/40"
            />
          </div>

          <SignalsDropdown
            signals={[
              { id: "zeroDay", label: "Zero-Day", icon: <Flame className="w-3 h-3" />, color: "red", on: zeroDayOnly, set: setZeroDayOnly },
              { id: "poc", label: "Has PoC", icon: <Github className="w-3 h-3" />, color: "purple", on: pocOnly, set: setPocOnly },
              { id: "itw", label: "In-the-Wild", icon: <Radio className="w-3 h-3" />, color: "amber", on: itwOnly, set: setItwOnly },
              { id: "nuclei", label: "Nuclei Template", icon: <Crosshair className="w-3 h-3" />, color: "cyan", on: nucleiOnly, set: setNucleiOnly },
              { id: "kev", label: "KEV Only", icon: <Bug className="w-3 h-3" />, color: "red", on: kevOnly, set: setKevOnly },
              { id: "linux", label: "Linux Infra", icon: <Linkedin className="w-3 h-3 rotate-90" />, color: "amber", on: linuxOnly, set: setLinuxOnly },
            ]}
            onChange={() => setPage(0)}
          />
          {(sevFilter.size > 0 ||
            srcFilter.size > 0 ||
            catFilter.size > 0 ||
            kevOnly ||
            linuxOnly ||
            pocOnly ||
            zeroDayOnly ||
            itwOnly ||
            nucleiOnly ||
            query) && (
            <button
              onClick={() => {
                setSev(new Set());
                setSrc(new Set());
                setCat(new Set());
                setKevOnly(false);
                setLinuxOnly(false);
                setPocOnly(false);
                setZeroDayOnly(false);
                setItwOnly(false);
                setNucleiOnly(false);
                setQuery("");
              }}
              className="h-9 px-3 rounded-lg border border-white/10 text-[11px] font-mono text-slate-400 hover:text-white hover:border-cyber-cyan/40 transition flex items-center gap-1.5"
            >
              <X className="w-3 h-3" /> clear
            </button>
          )}

          {/* Column picker */}
          <div className="relative" ref={colMenuRef}>
            <button
              onClick={() => setColMenuOpen((v) => !v)}
              className={cn(
                "h-9 px-3 rounded-lg border text-[11px] font-mono transition flex items-center gap-1.5",
                colMenuOpen
                  ? "border-cyber-cyan/50 text-cyber-cyan bg-cyber-cyan/10"
                  : "border-white/10 text-slate-400 hover:text-white hover:border-cyber-cyan/40"
              )}
            >
              <Columns3 className="w-3.5 h-3.5" /> columns
              <span className="text-[10px] text-slate-500">
                {visibleCols.size}/{ALL_COLS.length}
              </span>
            </button>
            {colMenuOpen && (
              <div className="absolute right-0 top-full mt-2 w-56 rounded-lg border border-white/10 bg-bg-elev/95 backdrop-blur shadow-2xl z-50 p-1.5 max-h-[min(70vh,420px)] overflow-y-auto overscroll-contain">
                <div className="sticky top-0 -mx-1.5 px-3.5 py-1.5 text-[10px] uppercase tracking-widest text-slate-500 font-mono flex items-center justify-between bg-bg-elev/95 backdrop-blur border-b border-white/5">
                  <span>Visible Columns</span>
                  <button
                    onClick={() =>
                      setVisibleCols(new Set(ALL_COLS.map((c) => c.id)))
                    }
                    className="text-[10px] text-cyber-cyan hover:underline normal-case"
                  >
                    all
                  </button>
                </div>
                {ALL_COLS.map((c) => {
                  const on = visibleCols.has(c.id);
                  return (
                    <button
                      key={c.id}
                      onClick={() => toggleCol(c.id)}
                      className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-[12px] text-slate-300 hover:bg-white/5 transition"
                    >
                      <span
                        className={cn(
                          "w-4 h-4 rounded border flex items-center justify-center transition",
                          on
                            ? "border-cyber-cyan bg-cyber-cyan/20 text-cyber-cyan"
                            : "border-white/15 text-transparent"
                        )}
                      >
                        <Check className="w-3 h-3" />
                      </span>
                      <span className="font-mono">{c.label}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Compact filter dropdowns — replaces three inline rows */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-slate-500 font-mono pr-2 border-r border-white/5">
            <Filter className="w-3 h-3" /> Refine
          </div>
          <FilterDropdown
            label="Severity"
            values={SEVERITIES}
            selected={sevFilter as Set<string>}
            onToggle={(v) => toggle(sevFilter, v as Severity, setSev)}
            onClear={() => setSev(new Set())}
            colorFor={(v) => SEVERITY_COLORS[v as Severity]}
          />
          <FilterDropdown
            label="Source"
            values={SOURCES as unknown as string[]}
            selected={srcFilter}
            onToggle={(v) => toggle(srcFilter, v, setSrc)}
            onClear={() => setSrc(new Set())}
          />
          <FilterDropdown
            label="Category"
            values={CATEGORIES}
            selected={catFilter}
            onToggle={(v) => toggle(catFilter, v, setCat)}
            onClear={() => setCat(new Set())}
          />

          {/* Inline chips showing current selections */}
          {[...sevFilter, ...srcFilter, ...catFilter].length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap pl-2 ml-1 border-l border-white/5">
              {[...sevFilter].map((v) => (
                <ActiveChip
                  key={`sev-${v}`}
                  label={v}
                  color={SEVERITY_COLORS[v as Severity]}
                  onRemove={() => toggle(sevFilter, v, setSev)}
                />
              ))}
              {[...srcFilter].map((v) => (
                <ActiveChip
                  key={`src-${v}`}
                  label={v}
                  onRemove={() => toggle(srcFilter, v, setSrc)}
                />
              ))}
              {[...catFilter].map((v) => (
                <ActiveChip
                  key={`cat-${v}`}
                  label={v}
                  onRemove={() => toggle(catFilter, v, setCat)}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="glass overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-[12.5px]">
            <thead className="bg-bg-elev/60 sticky top-0 backdrop-blur z-10">
              <tr className="text-left text-[10px] uppercase tracking-widest text-slate-500 font-mono">
                {ALL_COLS.filter((c) => visibleCols.has(c.id)).map((c) => {
                  const active = sort.key === c.id;
                  return (
                    <th key={c.id} className="px-4 py-3 font-medium">
                      <button
                        onClick={() => onSort(c.id)}
                        className={cn(
                          "flex items-center gap-1.5 uppercase tracking-widest transition",
                          active
                            ? "text-cyber-cyan"
                            : "text-slate-500 hover:text-slate-300"
                        )}
                        title={`Sort by ${c.label}`}
                      >
                        {c.label}
                        {active ? (
                          sort.dir === "asc" ? (
                            <ArrowUp className="w-3 h-3" />
                          ) : (
                            <ArrowDown className="w-3 h-3" />
                          )
                        ) : (
                          <ChevronsUpDown className="w-3 h-3 opacity-40" />
                        )}
                      </button>
                    </th>
                  );
                })}
                <th className="px-4 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {loading && rows.length === 0 && <SkeletonRows visibleCount={visibleCols.size} />}
              {!loading && rows.length === 0 && (
                <tr>
                  <td
                    colSpan={visibleCols.size + 1}
                    className="px-4 py-12 text-center text-slate-500 font-mono text-sm"
                  >
                    {windowBasis === "published" ? (
                      <>
                        <div>No CVEs were <span className="text-cyber-cyan">published</span> in this window.</div>
                        <div className="mt-2 text-[11px] text-slate-600">
                          Most recent publish in feed:{" "}
                          <span className="text-slate-400">{latestPublishedStr ?? "unknown"}</span>
                          {" · "}NVD typically pauses on weekends &amp; US holidays.
                          {" · "}
                          <button
                            onClick={() => setWindowBasis("modified")}
                            className="text-cyber-cyan hover:underline"
                          >
                            switch to Modified
                          </button>
                        </div>
                      </>
                    ) : (
                      "No CVEs match the current filters."
                    )}
                  </td>
                </tr>
              )}
              {rows.map((r) => (
                <tr
                  key={`${r.source}-${r.id}`}
                  onClick={() => openCve(r)}
                  className="group hover:bg-cyber-cyan/[0.04] cursor-pointer transition"
                >
                  {ALL_COLS.filter((c) => visibleCols.has(c.id)).map((c) => (
                    <Cell key={c.id} col={c.id} r={r} />
                  ))}
                  <td className="px-4 py-3 text-right">
                    <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyber-cyan transition" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-white/5 text-[11px] font-mono text-slate-400">
          <div>
            Page {safePage + 1} / {pageCount} · {filtered.length.toLocaleString()} records
          </div>
          <div className="flex gap-1">
            <button
              disabled={safePage === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="h-8 w-8 rounded-md border border-white/10 hover:border-cyber-cyan/40 disabled:opacity-30 flex items-center justify-center"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              disabled={safePage >= pageCount - 1}
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              className="h-8 w-8 rounded-md border border-white/10 hover:border-cyber-cyan/40 disabled:opacity-30 flex items-center justify-center"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

    </div>
  );
}

type SignalDef = {
  id: string;
  label: string;
  icon: React.ReactNode;
  color: "red" | "amber" | "cyan" | "purple";
  on: boolean;
  set: (v: boolean | ((p: boolean) => boolean)) => void;
};

function SignalsDropdown({
  signals,
  onChange,
}: {
  signals: SignalDef[];
  onChange?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onEsc);
    };
  }, [open]);

  const count = signals.filter((s) => s.on).length;
  const colorMap: Record<string, string> = {
    red: "text-cyber-red border-cyber-red/40 bg-cyber-red/10",
    amber: "text-cyber-amber border-cyber-amber/40 bg-cyber-amber/10",
    cyan: "text-cyber-cyan border-cyber-cyan/40 bg-cyber-cyan/10",
    purple: "text-cyber-purple border-cyber-purple/40 bg-cyber-purple/10",
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "h-9 px-3 rounded-lg border text-[11px] font-mono uppercase tracking-wider transition flex items-center gap-1.5",
          count > 0 || open
            ? "border-cyber-cyan/50 text-cyber-cyan bg-cyber-cyan/10"
            : "border-white/10 text-slate-400 hover:text-white hover:border-cyber-cyan/40"
        )}
      >
        <Filter className="w-3 h-3" />
        Signals
        {count > 0 && (
          <span className="ml-1 px-1.5 rounded-full bg-cyber-cyan/20 text-cyber-cyan text-[10px] leading-4">
            {count}
          </span>
        )}
        <ChevronsUpDown className="w-3 h-3 opacity-60" />
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-2 w-60 rounded-lg border border-white/10 bg-bg-elev/95 backdrop-blur shadow-2xl z-50 p-1.5">
          <div className="sticky top-0 -mx-1.5 px-3.5 py-1.5 text-[10px] uppercase tracking-widest text-slate-500 font-mono flex items-center justify-between bg-bg-elev/95 backdrop-blur border-b border-white/5">
            <span>Signals</span>
            {count > 0 && (
              <button
                onClick={() => {
                  signals.forEach((s) => s.set(false));
                  onChange?.();
                }}
                className="text-[10px] text-cyber-cyan hover:underline normal-case"
              >
                clear
              </button>
            )}
          </div>
          {signals.map((s) => (
            <button
              key={s.id}
              onClick={() => {
                s.set((v: boolean) => !v);
                onChange?.();
              }}
              className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-[12px] text-slate-300 hover:bg-white/5 transition"
            >
              <span
                className={cn(
                  "w-4 h-4 rounded border flex items-center justify-center transition shrink-0",
                  s.on
                    ? colorMap[s.color]
                    : "border-white/15 text-transparent"
                )}
              >
                <Check className="w-3 h-3" />
              </span>
              <span
                className={cn(
                  "inline-flex items-center gap-1.5 font-mono",
                  s.on ? colorMap[s.color].split(" ")[0] : ""
                )}
              >
                {s.icon}
                {s.label}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function FilterDropdown({
  label,
  values,
  selected,
  onToggle,
  onClear,
  colorFor,
}: {
  label: string;
  values: string[];
  selected: Set<string>;
  onToggle: (v: string) => void;
  onClear: () => void;
  colorFor?: (v: string) => string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onEsc);
    };
  }, [open]);

  const count = selected.size;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "h-9 px-3 rounded-lg border text-[11px] font-mono uppercase tracking-wider transition flex items-center gap-1.5",
          count > 0 || open
            ? "border-cyber-cyan/50 text-cyber-cyan bg-cyber-cyan/10"
            : "border-white/10 text-slate-400 hover:text-white hover:border-cyber-cyan/40"
        )}
      >
        <Filter className="w-3 h-3" />
        {label}
        {count > 0 && (
          <span className="ml-1 px-1.5 rounded-full bg-cyber-cyan/20 text-cyber-cyan text-[10px] leading-4">
            {count}
          </span>
        )}
        <ChevronsUpDown className="w-3 h-3 opacity-60" />
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-2 w-56 rounded-lg border border-white/10 bg-bg-elev/95 backdrop-blur shadow-2xl z-50 p-1.5 max-h-[min(70vh,420px)] overflow-y-auto overscroll-contain">
          <div className="sticky top-0 -mx-1.5 px-3.5 py-1.5 text-[10px] uppercase tracking-widest text-slate-500 font-mono flex items-center justify-between bg-bg-elev/95 backdrop-blur border-b border-white/5">
            <span>{label}</span>
            {count > 0 && (
              <button
                onClick={onClear}
                className="text-[10px] text-cyber-cyan hover:underline normal-case"
              >
                clear
              </button>
            )}
          </div>
          {values.map((v) => {
            const on = selected.has(v);
            const color = colorFor?.(v);
            return (
              <button
                key={v}
                onClick={() => onToggle(v)}
                className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-[12px] text-slate-300 hover:bg-white/5 transition"
              >
                <span
                  className={cn(
                    "w-4 h-4 rounded border flex items-center justify-center transition shrink-0",
                    on
                      ? "border-cyber-cyan bg-cyber-cyan/20 text-cyber-cyan"
                      : "border-white/15 text-transparent"
                  )}
                  style={
                    on && color
                      ? { color, borderColor: `${color}88`, background: `${color}20` }
                      : undefined
                  }
                >
                  <Check className="w-3 h-3" />
                </span>
                <span className="font-mono uppercase tracking-wider">{v}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ActiveChip({
  label,
  color,
  onRemove,
}: {
  label: string;
  color?: string;
  onRemove: () => void;
}) {
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10.5px] font-mono uppercase tracking-wider border bg-white/5 border-white/10 text-slate-300"
      style={
        color
          ? { color, borderColor: `${color}55`, background: `${color}18` }
          : undefined
      }
    >
      {label}
      <button
        onClick={onRemove}
        className="hover:text-white transition"
        aria-label={`Remove ${label} filter`}
      >
        <X className="w-3 h-3" />
      </button>
    </span>
  );
}

function SkeletonRows({ visibleCount = 11 }: { visibleCount?: number }) {
  return (
    <>
      {Array.from({ length: 8 }).map((_, i) => (
        <tr key={i}>
          {Array.from({ length: visibleCount + 1 }).map((_, j) => (
            <td key={j} className="px-4 py-3">
              <div className="h-3 rounded bg-white/5 shimmer" />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

function Cell({ col, r }: { col: ColId; r: CVERecord }) {
  switch (col) {
    case "cve":
      return (
        <td className="px-4 py-3">
          <div className="font-mono text-white flex items-center gap-1.5">
            {r.id}
            {r.isZeroDay && (
              <span
                className="chip border-cyber-red/50 text-cyber-red bg-cyber-red/15 font-mono shadow-glowRed"
                title={`Zero-day score ${r.zeroDayScore}/100`}
              >
                <Flame className="w-3 h-3" /> 0-DAY
              </span>
            )}
          </div>
          {r.exploited && (
            <div className="text-[10px] text-cyber-red font-mono uppercase tracking-wider">
              ● actively exploited
            </div>
          )}
        </td>
      );
    case "severity":
      return (
        <td className="px-4 py-3">
          <SeverityBadge severity={r.severity} />
        </td>
      );
    case "cvss":
      return (
        <td className="px-4 py-3 w-32">
          {r.cvss != null ? (
            <ScoreBar
              value={r.cvss}
              max={10}
              color={SEVERITY_COLORS[r.severity]}
            />
          ) : (
            <span className="text-slate-600 font-mono">—</span>
          )}
        </td>
      );
    case "epss":
      return (
        <td className="px-4 py-3 w-32">
          {r.epss != null ? (
            <ScoreBar
              value={r.epss * 100}
              max={100}
              color="#7C3AED"
              label={`${(r.epss * 100).toFixed(0)}%`}
            />
          ) : (
            <span className="text-slate-600 font-mono">—</span>
          )}
        </td>
      );
    case "intel":
      return (
        <td className="px-4 py-3 w-44">
          <ExploitIntelCell record={r} />
        </td>
      );
    case "vendor":
      return (
        <td className="px-4 py-3 text-slate-300 max-w-[220px] truncate">
          {r.vendor ?? "—"}{" "}
          <span className="text-slate-500">/ {r.product ?? "—"}</span>
        </td>
      );
    case "category":
      return (
        <td className="px-4 py-3">
          <span className="chip border-white/10 bg-white/5 text-slate-300 font-mono">
            {r.category}
          </span>
        </td>
      );
    case "source":
      return (
        <td className="px-4 py-3">
          <span className="text-[11px] font-mono text-slate-400">
            {r.source}
          </span>
        </td>
      );
    case "published":
      return (
        <td className="px-4 py-3 font-mono text-[11px] whitespace-nowrap">
          <div className="text-slate-300">
            {new Date(r.published).toLocaleDateString(undefined, {
              year: "numeric",
              month: "short",
              day: "2-digit",
            })}
          </div>
          <div className="text-slate-500 text-[10px]">
            {new Date(r.published).toLocaleTimeString(undefined, {
              hour: "2-digit",
              minute: "2-digit",
            })}
            <span className="text-slate-600"> · {timeAgo(r.published)}</span>
          </div>
        </td>
      );
    case "modified":
      return (
        <td className="px-4 py-3 font-mono text-[11px] whitespace-nowrap">
          <div className="text-slate-300">
            {new Date(r.modified).toLocaleDateString(undefined, {
              year: "numeric",
              month: "short",
              day: "2-digit",
            })}
          </div>
          <div className="text-slate-500 text-[10px]">
            {new Date(r.modified).toLocaleTimeString(undefined, {
              hour: "2-digit",
              minute: "2-digit",
            })}
            <span className="text-slate-600"> · {timeAgo(r.modified)}</span>
          </div>
        </td>
      );
  }
}

export function DetailDrawer({
  record,
  onClose,
}: {
  record: CVERecord;
  onClose: () => void;
}) {
  const [aiOpen, setAiOpen] = useState(false);
  const [aiQuestion, setAiQuestion] = useState(
    "Explain the security impact, likely exposure, and what a SOC should do next."
  );
  const [aiModels, setAiModels] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState<string>(() => {
    try {
      const saved = localStorage.getItem("zsg-ai-model");
      return saved || "llama3.2";
    } catch {
      return "llama3.2";
    }
  });
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiResponse, setAiResponse] = useState<string | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem("zsg-ai-model", selectedModel);
    } catch {}
  }, [selectedModel]);

  async function loadModels() {
    try {
      const models = await listOllamaModels();
      setAiModels(models);
      if (models.length > 0 && !models.includes(selectedModel)) {
        setSelectedModel(models[0]);
      }
    } catch {
      setAiModels([]);
    }
  }

  useEffect(() => {
    if (!aiOpen) return;
    void loadModels();
  }, [aiOpen]);

  const handleAiAsk = async (e?: FormEvent<HTMLFormElement>) => {
    e?.preventDefault();
    setAiLoading(true);
    setAiError(null);
    try {
      const result = await askAiAboutCve({
        cve: record,
        question: aiQuestion,
        model: selectedModel || undefined,
      });
      setAiResponse(result.response);
    } catch (err) {
      setAiError(
        err instanceof Error
          ? err.message
          : "The local Ollama model could not respond. Start `ollama serve` and pull a model such as `llama3.2`."
      );
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
        className="fixed inset-0 bg-bg/70 backdrop-blur-sm z-40"
      />
      <motion.aside
        initial={{ x: "100%" }}
        animate={{ x: 0 }}
        exit={{ x: "100%" }}
        transition={{ type: "spring", damping: 28, stiffness: 240 }}
        className="fixed right-0 top-0 bottom-0 w-full sm:w-[520px] z-50 bg-bg-panel/95 backdrop-blur-xl border-l border-white/10 overflow-y-auto"
      >
        <div className="sticky top-0 bg-bg-panel/95 backdrop-blur-xl border-b border-white/10 p-5 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={record.severity} />
              {record.isZeroDay && (
                <span className="chip border-cyber-red/50 text-cyber-red bg-cyber-red/15 font-mono shadow-glowRed">
                  <Flame className="w-3 h-3" /> 0-DAY {record.zeroDayScore}
                </span>
              )}
              {record.exploited && (
                <span className="chip border-cyber-red/40 text-cyber-red bg-cyber-red/10 font-mono">
                  <Bug className="w-3 h-3" /> KEV
                </span>
              )}
              {(record.pocs?.length ?? 0) > 0 && (
                <span className="chip border-cyber-purple/40 text-cyber-purple bg-cyber-purple/10 font-mono">
                  <Github className="w-3 h-3" /> {record.pocs?.length} PoC
                </span>
              )}
              {(record.inTheWild?.length ?? 0) > 0 && (
                <span className="chip border-cyber-amber/40 text-cyber-amber bg-cyber-amber/10 font-mono">
                  <Radio className="w-3 h-3" /> ITW
                </span>
              )}
            </div>
            <h2 className="font-display text-xl font-semibold text-white mt-2 tracking-wide">
              {record.id}
            </h2>
            <div className="text-[11px] text-slate-500 font-mono">
              {record.source} · modified {timeAgo(record.modified)}
            </div>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              onClick={onClose}
              className="h-8 w-8 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:border-cyber-cyan/40 flex items-center justify-center"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="p-5 space-y-5">
          {record.enrichmentSources && record.enrichmentSources.length > 0 && (
            <section className="rounded-lg border border-cyber-amber/30 bg-cyber-amber/[0.06] p-3">
              <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-cyber-amber font-mono mb-2">
                <Filter className="w-3 h-3" /> Info not yet in NVD — alternate sources
              </div>
              <ul className="space-y-1.5 text-[12px] text-slate-300">
                {record.enrichmentSources.map((s, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="mt-1 w-1 h-1 rounded-full bg-cyber-amber/70 shrink-0" />
                    <div className="flex-1 min-w-0">
                      {s.url ? (
                        <a
                          href={s.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-cyber-cyan hover:underline font-mono break-all"
                        >
                          {s.label}
                        </a>
                      ) : (
                        <span className="font-mono">{s.label}</span>
                      )}
                      {s.description && (
                        <div className="text-slate-400 leading-snug mt-0.5">
                          {s.description}
                        </div>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          )}
          <section>
            <SectionLabel>Description</SectionLabel>
            <p className="text-[13px] leading-relaxed text-slate-300 whitespace-pre-line">
              {record.description || "No description provided by source."}
            </p>
          </section>

          <section className="rounded-xl border border-cyber-cyan/20 bg-cyber-cyan/5 p-4">
            <div className="flex items-center justify-between gap-2">
              <SectionLabel>
                <span className="flex items-center gap-1.5 text-cyber-cyan">
                  <Sparkles className="w-3 h-3" /> AI Security Analyst
                </span>
              </SectionLabel>
              <button
                type="button"
                onClick={() => setAiOpen((v) => !v)}
                className="text-[10px] uppercase tracking-widest text-cyber-cyan hover:underline font-mono"
              >
                {aiOpen ? "Hide" : "Open"}
              </button>
            </div>

            {aiOpen && (
              <form onSubmit={handleAiAsk} className="space-y-3 mt-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <label className="text-[10px] uppercase tracking-widest text-slate-500 font-mono">
                    Model
                  </label>
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="h-8 rounded-lg border border-white/10 bg-bg-elev/80 px-2 text-[11px] font-mono text-slate-200"
                  >
                    {aiModels.length > 0 ? (
                      aiModels.map((m) => (
                        <option key={m} value={m}>{m}</option>
                      ))
                    ) : (
                      <option value={selectedModel}>{selectedModel}</option>
                    )}
                  </select>
                </div>
                <textarea
                  value={aiQuestion}
                  onChange={(e) => setAiQuestion(e.target.value)}
                  rows={3}
                  className="w-full rounded-lg border border-white/10 bg-bg-elev/80 p-3 text-[12px] text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyber-cyan/40"
                  placeholder="Ask the local AI analyst about risk, exploitability, or remediation."
                />
                <div className="flex items-center justify-between gap-2">
                  <button
                    type="submit"
                    disabled={aiLoading}
                    className="inline-flex items-center gap-2 rounded-lg border border-cyber-cyan/40 bg-cyber-cyan/10 px-3 py-2 text-[11px] font-mono uppercase tracking-wider text-cyber-cyan disabled:opacity-50"
                  >
                    <Sparkles className={cn("w-3 h-3", aiLoading && "animate-pulse")} />
                    {aiLoading ? "Thinking…" : "Ask AI"}
                  </button>
                  <span className="text-[10px] text-slate-500 font-mono">
                    local Ollama
                  </span>
                </div>
              </form>
            )}

            {aiError && (
              <div className="mt-3 rounded-lg border border-cyber-red/20 bg-cyber-red/5 p-3 text-[12px] text-cyber-red font-mono leading-relaxed">
                {aiError}
              </div>
            )}

            {aiResponse && (
              <div className="mt-3 rounded-lg border border-white/10 bg-bg-elev/70 p-3 text-[12px] leading-relaxed text-slate-200 whitespace-pre-line">
                {aiResponse}
              </div>
            )}

            {!aiOpen && !aiResponse && !aiError && (
              <div className="mt-3 text-[12px] text-slate-400 font-mono">
                Ask the local model to explain the CVE, prioritize the risk, and suggest next steps.
              </div>
            )}
          </section>

          <div className="grid grid-cols-2 gap-3">
            <MetricBox label="CVSS Base">
              {record.cvss != null ? (
                <ScoreBar
                  value={record.cvss}
                  color={SEVERITY_COLORS[record.severity]}
                />
              ) : (
                <span className="text-slate-500 font-mono">unscored</span>
              )}
            </MetricBox>
            <MetricBox label="EPSS Probability">
              {record.epss != null ? (
                <>
                  <ScoreBar
                    value={record.epss * 100}
                    max={100}
                    color="#7C3AED"
                    label={`${(record.epss * 100).toFixed(1)}%`}
                  />
                  <div className="text-[10px] font-mono text-slate-500 mt-1.5 flex justify-between">
                    <span>
                      {record.epssSource === "FIRST.org" ? (
                        <span className="text-cyber-green">● FIRST.org · {record.epssDate ?? "daily"}</span>
                      ) : (
                        <span className="text-slate-500">● heuristic (no FIRST record)</span>
                      )}
                    </span>
                    {record.epssPercentile != null && (
                      <span>{(record.epssPercentile * 100).toFixed(1)}%ile</span>
                    )}
                  </div>
                </>
              ) : (
                <span className="text-slate-500 font-mono">—</span>
              )}
            </MetricBox>
          </div>

          {record.cvssVector && (
            <section>
              <SectionLabel>CVSS Vector</SectionLabel>
              <code className="block text-[11px] font-mono text-cyber-cyan bg-bg-elev/60 border border-white/5 rounded-lg p-3 break-all">
                {record.cvssVector}
              </code>
            </section>
          )}

          <section className="grid grid-cols-2 gap-3">
            <Field label="Vendor" value={record.vendor} />
            <Field label="Product" value={record.product} />
            <Field label="Category" value={record.category} />
            <Field label="Published" value={new Date(record.published).toLocaleString()} />
          </section>

          {record.tags && record.tags.length > 0 && (
            <section>
              <SectionLabel>Tags</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {record.tags.map((t) => (
                  <span
                    key={t}
                    className="chip border-white/10 bg-white/5 text-slate-300 font-mono"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </section>
          )}

          {record.references && record.references.length > 0 && (
            <section>
              <SectionLabel>References</SectionLabel>
              <ul className="space-y-1.5">
                {record.references.map((u) => (
                  <li key={u}>
                    <a
                      href={u}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center gap-2 text-[12px] text-cyber-cyan hover:underline truncate"
                    >
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">{u}</span>
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {(record.zeroDayScore ?? 0) > 0 && (
            <section className="rounded-xl border border-cyber-red/20 bg-cyber-red/5 p-4">
              <div className="flex items-center justify-between mb-2">
                <SectionLabel>
                  <span className="flex items-center gap-1.5">
                    <Flame className="w-3 h-3 text-cyber-red" /> Zero-Day Likelihood
                  </span>
                </SectionLabel>
                <span className="font-display text-2xl font-bold text-cyber-red neon-text">
                  {record.zeroDayScore}/100
                </span>
              </div>
              <ScoreBar
                value={record.zeroDayScore ?? 0}
                max={100}
                color="#EF4444"
                label={record.isZeroDay ? "0-DAY" : "elev."}
              />
              <p className="text-[11px] text-slate-400 mt-2 font-mono leading-relaxed">
                Composite signal from KEV timing, PoC publication date, CVSS,
                in-the-wild events &amp; NVD vulnStatus.
              </p>
            </section>
          )}

          {record.pocs && record.pocs.length > 0 && (
            <section>
              <SectionLabel>
                <span className="flex items-center gap-1.5">
                  <Github className="w-3 h-3" /> Public Proof-of-Concept · {record.pocs.length}
                </span>
              </SectionLabel>
              <ul className="space-y-1.5 max-h-64 overflow-auto pr-1">
                {record.pocs.slice(0, 25).map((p) => (
                  <li
                    key={p.url}
                    className="rounded-lg border border-white/5 bg-bg-elev/40 p-2.5 hover:border-cyber-purple/40 transition"
                  >
                    <a
                      href={p.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[12.5px] font-mono text-cyber-purple hover:underline flex items-center gap-2"
                    >
                      <Github className="w-3 h-3 shrink-0" />
                      <span className="truncate">
                        {p.owner ? `${p.owner}/` : ""}{p.name}
                      </span>
                      <span className="ml-auto text-[10px] text-cyber-amber">
                        ★ {p.stars}
                      </span>
                    </a>
                    {p.description && (
                      <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                        {p.description}
                      </p>
                    )}
                    {p.createdAt && (
                      <p className="text-[10px] text-slate-500 font-mono mt-1">
                        created {new Date(p.createdAt).toLocaleDateString()} ·
                        updated {p.updatedAt ? timeAgo(p.updatedAt) : "—"}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {record.exploits && record.exploits.length > 0 && (
            <section>
              <SectionLabel>
                <span className="flex items-center gap-1.5">
                  <Bug className="w-3 h-3" /> Exploit-DB · {record.exploits.length}
                </span>
              </SectionLabel>
              <ul className="space-y-1.5 max-h-56 overflow-auto pr-1">
                {record.exploits.slice(0, 20).map((e) => (
                  <li key={e.edbId} className="rounded-lg border border-white/5 bg-bg-elev/40 p-2.5">
                    <a
                      href={e.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[12.5px] text-cyber-amber hover:underline flex items-center gap-2"
                    >
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">EDB-{e.edbId} · {e.title}</span>
                    </a>
                    <p className="text-[10px] text-slate-500 font-mono mt-1">
                      {[e.type, e.platform, e.author, e.date].filter(Boolean).join(" · ")}
                    </p>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {record.nucleiTemplates && record.nucleiTemplates.length > 0 && (
            <section>
              <SectionLabel>
                <span className="flex items-center gap-1.5">
                  <Crosshair className="w-3 h-3" /> Nuclei Templates · {record.nucleiTemplates.length}
                </span>
              </SectionLabel>
              <ul className="space-y-1.5 max-h-56 overflow-auto pr-1">
                {record.nucleiTemplates.slice(0, 20).map((t) => (
                  <li
                    key={t.templateId + t.filePath}
                    className="rounded-lg border border-cyber-cyan/20 bg-cyber-cyan/5 p-2.5"
                  >
                    <a
                      href={t.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[12.5px] text-cyber-cyan hover:underline flex items-center gap-2"
                    >
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">{t.name}</span>
                    </a>
                    <div className="flex items-center gap-1.5 flex-wrap mt-1.5">
                      <span
                        className={cn(
                          "chip font-mono text-[10px]",
                          t.severity === "critical" &&
                            "border-cyber-red/40 text-cyber-red bg-cyber-red/10",
                          t.severity === "high" &&
                            "border-cyber-red/30 text-cyber-red bg-cyber-red/5",
                          t.severity === "medium" &&
                            "border-cyber-amber/40 text-cyber-amber bg-cyber-amber/10",
                          (t.severity === "low" || t.severity === "info") &&
                            "border-cyber-green/30 text-cyber-green bg-cyber-green/10",
                          t.severity === "unknown" &&
                            "border-white/10 text-slate-400 bg-white/5"
                        )}
                      >
                        {t.severity}
                      </span>
                      {t.tags.slice(0, 6).map((tag) => (
                        <span
                          key={tag}
                          className="chip border-white/10 text-slate-400 bg-white/5 font-mono text-[10px]"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                    <p className="text-[10px] text-slate-500 font-mono mt-1 truncate">
                      {t.filePath}
                      {t.author ? ` · by ${t.author}` : ""}
                    </p>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {record.inTheWild && record.inTheWild.length > 0 && (
            <section>
              <SectionLabel>
                <span className="flex items-center gap-1.5">
                  <Radio className="w-3 h-3" /> In-the-Wild Events · {record.inTheWild.length}
                </span>
              </SectionLabel>
              <ul className="space-y-1.5 max-h-56 overflow-auto pr-1">
                {record.inTheWild.slice(0, 20).map((e, i) => (
                  <li key={i} className="rounded-lg border border-cyber-red/20 bg-cyber-red/5 p-2.5">
                    <div className="flex items-center gap-2 text-[12px] text-cyber-red font-mono">
                      <Radio className="w-3 h-3" />
                      <span>{e.source ?? "inthewild"}</span>
                      <span className="text-slate-500 ml-auto">
                        {e.timestamp ? timeAgo(e.timestamp) : ""}
                      </span>
                    </div>
                    {e.referenceURL && (
                      <a
                        href={e.referenceURL}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-cyber-cyan hover:underline truncate block mt-1"
                      >
                        {e.referenceURL}
                      </a>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {record.kev && (
            <section>
              <SectionLabel>
                <span className="flex items-center gap-1.5">
                  <Bug className="w-3 h-3 text-cyber-red" /> CISA KEV Mandate
                </span>
              </SectionLabel>
              <div className="rounded-xl border border-cyber-red/20 bg-cyber-red/5 p-3 space-y-1.5 text-[12px]">
                <div className="flex justify-between font-mono">
                  <span className="text-slate-500">Added</span>
                  <span className="text-white">{new Date(record.kev.dateAdded).toLocaleDateString()}</span>
                </div>
                <div className="flex justify-between font-mono">
                  <span className="text-slate-500">Due</span>
                  <span className="text-cyber-amber">{new Date(record.kev.dueDate).toLocaleDateString()}</span>
                </div>
                {record.kev.ransomware && (
                  <div className="text-cyber-purple font-mono text-[11px]">⚠ Known ransomware campaign use</div>
                )}
                {record.kev.requiredAction && (
                  <p className="text-slate-300 leading-relaxed pt-1 border-t border-white/5">
                    {record.kev.requiredAction}
                  </p>
                )}
              </div>
            </section>
          )}
        </div>
      </motion.aside>
    </>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] uppercase tracking-widest text-slate-500 font-mono mb-2">
      {children}
    </div>
  );
}

function MetricBox({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-white/5 bg-bg-elev/60 p-3">
      <SectionLabel>{label}</SectionLabel>
      {children}
    </div>
  );
}

function Field({ label, value }: { label: string; value?: string }) {
  return (
    <div>
      <SectionLabel>{label}</SectionLabel>
      <div className="text-[12.5px] text-slate-200 font-mono">{value ?? "—"}</div>
    </div>
  );
}

function ExploitIntelCell({ record }: { record: CVERecord }) {
  const poc = record.pocs?.length ?? 0;
  const exp = record.exploits?.length ?? 0;
  const itw = record.inTheWild?.length ?? 0;
  const nuc = record.nucleiTemplates?.length ?? 0;
  if (poc + exp + itw + nuc === 0)
    return <span className="text-slate-600 font-mono text-[11px]">no signals</span>;
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {poc > 0 && (
        <span
          className="chip border-cyber-purple/40 text-cyber-purple bg-cyber-purple/10 font-mono"
          title={`${poc} GitHub PoC repos`}
        >
          <Github className="w-3 h-3" /> {poc}
        </span>
      )}
      {exp > 0 && (
        <span
          className="chip border-cyber-amber/40 text-cyber-amber bg-cyber-amber/10 font-mono"
          title={`${exp} Exploit-DB entries`}
        >
          <Bug className="w-3 h-3" /> {exp}
        </span>
      )}
      {nuc > 0 && (
        <span
          className="chip border-cyber-cyan/40 text-cyber-cyan bg-cyber-cyan/10 font-mono"
          title={`${nuc} Nuclei scanner template${nuc === 1 ? "" : "s"}`}
        >
          <Crosshair className="w-3 h-3" /> {nuc}
        </span>
      )}
      {itw > 0 && (
        <span
          className="chip border-cyber-red/40 text-cyber-red bg-cyber-red/10 font-mono"
          title={`${itw} in-the-wild events`}
        >
          <Radio className="w-3 h-3" /> {itw}
        </span>
      )}
    </div>
  );
}
