import { useMemo } from "react";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";
import { SeverityBadge } from "../ui/SeverityBadge";
import { Flame, Github, Bug, Radio, ExternalLink } from "lucide-react";
import { timeAgo } from "@/lib/utils";
import { Link } from "react-router-dom";
import type { CVERecord } from "@/lib/types";

// Backend merger emits a placeholder description like
// "⚠️ Not yet published in NVD or MITRE — details sourced from <repo>.\n\n<real summary>"
// for POC-ONLY entries. Show the real PoC summary (or the repo name) instead
// of leaking the banner into the list.
const PLACEHOLDER_BANNER_RE =
  /^\s*[⚠️\u26A0\uFE0F]*\s*Not yet published[^\n]*(?:\n+|$)/i;

function describe(r: CVERecord): string {
  if (r.product) return r.product;
  const desc = (r.description ?? "").trim();
  if (desc && !PLACEHOLDER_BANNER_RE.test(desc)) {
    return desc.slice(0, 80);
  }
  // Strip the banner and use whatever real text follows it.
  const after = desc.replace(PLACEHOLDER_BANNER_RE, "").trim();
  if (after) return after.slice(0, 80);
  // Fall back to the PoC repo's own description, then its name.
  const poc = r.pocs?.[0];
  if (poc?.description) return poc.description.slice(0, 80);
  if (poc?.name) return `PoC: ${poc.name}`;
  return "PoC-only · no NVD details yet";
}

// Derive a short "what changed recently" signal so the row tells the user
// *why* this CVE is here (brand new disclosure, fresh PoC, KEV-added, etc.).
type ChangeSignal = {
  label: string;
  title: string;
  tone: "red" | "amber" | "purple" | "cyan" | "slate";
};

const DAY = 24 * 60 * 60 * 1000;

function whatChanged(r: CVERecord): ChangeSignal | null {
  const now = Date.now();
  const pubAge = r.published ? now - Date.parse(r.published) : Infinity;
  const modAge = r.modified ? now - Date.parse(r.modified) : Infinity;

  // 1. PoC activity is the most verifiable signal (GitHub timestamps),
  //    so check it BEFORE trusting NVD's published date.
  const pocs = r.pocs ?? [];
  let oldestPocCreated = Infinity;
  let newestPocCreated = 0;
  let newestPocUpdated = 0;
  for (const p of pocs) {
    const c = p.createdAt ? Date.parse(p.createdAt) : NaN;
    const u = p.updatedAt ? Date.parse(p.updatedAt) : NaN;
    if (Number.isFinite(c)) {
      if (c < oldestPocCreated) oldestPocCreated = c;
      if (c > newestPocCreated) newestPocCreated = c;
    }
    if (Number.isFinite(u) && u > newestPocUpdated) newestPocUpdated = u;
  }
  const newestPocCreatedAge = newestPocCreated ? now - newestPocCreated : Infinity;
  const newestPocUpdatedAge = newestPocUpdated ? now - newestPocUpdated : Infinity;

  if (pocs.length > 0 && newestPocCreatedAge <= 14 * DAY) {
    const days = Math.max(1, Math.round(newestPocCreatedAge / DAY));
    return {
      label: pocs.length === 1 ? "+1 PoC" : `+${pocs.length} PoCs`,
      title: `Latest PoC repo created ${days}d ago (${pocs.length} total)`,
      tone: "purple",
    };
  }

  // 2. Genuinely new disclosure: NVD published within 7d AND no PoC
  //    predates that publish date (otherwise the vuln was already public).
  if (pubAge <= 7 * DAY) {
    const pubTs = Date.parse(r.published ?? "");
    const pocPredatesPublish =
      Number.isFinite(oldestPocCreated) && oldestPocCreated < pubTs - DAY;
    if (!pocPredatesPublish) {
      const days = Math.max(1, Math.round(pubAge / DAY));
      return {
        label: `Disclosed ${days}d`,
        title: `NVD published ${days}d ago — no earlier PoC found`,
        tone: "red",
      };
    }
  }

  // 3. PoC repo refreshed recently (existing PoC got new commits).
  if (pocs.length > 0 && newestPocUpdatedAge <= 7 * DAY) {
    const days = Math.max(1, Math.round(newestPocUpdatedAge / DAY));
    return {
      label: "PoC updated",
      title: `PoC repo pushed ${days}d ago`,
      tone: "purple",
    };
  }

  // 4. KEV / in-the-wild / exploit-DB signals.
  if (r.kev?.dateAdded) {
    const kevAge = now - Date.parse(r.kev.dateAdded);
    if (Number.isFinite(kevAge) && kevAge <= 30 * DAY) {
      const days = Math.max(1, Math.round(kevAge / DAY));
      return {
        label: "KEV added",
        title: `Added to CISA KEV ${days}d ago`,
        tone: "red",
      };
    }
  }
  if ((r.inTheWild?.length ?? 0) > 0) {
    return {
      label: "In-the-wild",
      title: "Reported exploited in the wild",
      tone: "amber",
    };
  }
  if ((r.exploits?.length ?? 0) > 0) {
    return {
      label: "Exploit-DB",
      title: "Exploit module published on Exploit-DB",
      tone: "amber",
    };
  }

  // 5. NVD record metadata refreshed within last 7d (rescore / status change).
  if (modAge <= 7 * DAY) {
    const days = Math.max(1, Math.round(modAge / DAY));
    return {
      label: `Updated ${days}d`,
      title: `NVD record updated ${days}d ago`,
      tone: "cyan",
    };
  }

  return null;
}

const SIGNAL_CLASSES: Record<ChangeSignal["tone"], string> = {
  red: "border-cyber-red/40 text-cyber-red bg-cyber-red/10",
  amber: "border-cyber-amber/40 text-cyber-amber bg-cyber-amber/10",
  purple: "border-cyber-purple/40 text-cyber-purple bg-cyber-purple/10",
  cyan: "border-cyber-cyan/40 text-cyber-cyan bg-cyber-cyan/10",
  slate: "border-white/10 text-slate-400 bg-white/5",
};

export default function ZeroDayPanel() {
  const records = useStore((s) => s.records);
  const backendOnline = useStore((s) => s.backendOnline);
  const counts = useStore((s) => s.counts);

  const top = useMemo(() => {
    const WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // last 30 days
    const cutoff = Date.now() - WINDOW_MS;
    const inWindow = (r: (typeof records)[number]) => {
      // Window is based on PUBLISHED date, not modified, so old CVEs that
      // just got a new PoC indexed (e.g. CVE-2021-21735) don't leak in.
      const t = Date.parse(r.published ?? r.modified ?? "");
      return Number.isFinite(t) && t >= cutoff;
    };
    const candidates = records.filter(
      (r) => r.isZeroDay || (r.pocs?.length ?? 0) > 0
    );
    const recent = candidates
      .filter(inWindow)
      .sort((a, b) => {
        // Sort by most recently modified/published first.
        const dt =
          Date.parse(b.modified ?? b.published ?? "0") -
          Date.parse(a.modified ?? a.published ?? "0");
        if (dt !== 0) return dt;
        // Tiebreak on zero-day score so hotter items win identical timestamps.
        return (b.zeroDayScore ?? 0) - (a.zeroDayScore ?? 0);
      });
    if (recent.length >= 8) return recent.slice(0, 8);
    // Fallback: backfill with the most recently modified candidates that
    // fell outside the window so the panel never goes empty.
    const filler = candidates
      .filter((r) => !inWindow(r))
      .sort(
        (a, b) =>
          Date.parse(b.modified ?? b.published ?? "0") -
          Date.parse(a.modified ?? a.published ?? "0")
      );
    return [...recent, ...filler].slice(0, 8);
  }, [records]);

  return (
    <Panel
      title="Zero-Day & PoC Intelligence"
      subtitle={
        backendOnline
          ? `Correlated from GitHub PoCs · Exploit-DB · inthewild.io — last 30d`
          : "⚠ Backend offline — run `npm run dev:server` to enable PoC correlation"
      }
      accent="red"
      delay={0.22}
      right={
        backendOnline ? (
          <div className="chip border-cyber-red/30 text-cyber-red bg-cyber-red/10 font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-cyber-red animate-pulse" />
            LIVE CORRELATION
          </div>
        ) : (
          <div className="chip border-cyber-amber/30 text-cyber-amber bg-cyber-amber/10 font-mono">
            DEGRADED
          </div>
        )
      }
    >
      <div className="grid grid-cols-4 gap-2 mb-3">
        <SignalBox
          label="0-Day"
          value={counts?.zeroDay ?? 0}
          icon={<Flame className="w-3 h-3" />}
          color="text-cyber-red border-cyber-red/30 bg-cyber-red/5"
        />
        <SignalBox
          label="With PoC"
          value={counts?.pocTracked ?? 0}
          icon={<Github className="w-3 h-3" />}
          color="text-cyber-purple border-cyber-purple/30 bg-cyber-purple/5"
        />
        <SignalBox
          label="Exploit-DB"
          value={counts?.exploitDb ?? 0}
          icon={<Bug className="w-3 h-3" />}
          color="text-cyber-amber border-cyber-amber/30 bg-cyber-amber/5"
        />
        <SignalBox
          label="In-the-Wild"
          value={counts?.inTheWild ?? 0}
          icon={<Radio className="w-3 h-3" />}
          color="text-cyber-cyan border-cyber-cyan/30 bg-cyber-cyan/5"
        />
      </div>

      <ul className="space-y-1.5 max-h-[280px] overflow-auto pr-1">
        {top.length === 0 && (
          <li className="text-[11px] text-slate-500 font-mono py-4 text-center">
            {backendOnline
              ? "No PoC-tracked or zero-day-grade CVEs in current window."
              : "Start the backend to populate PoC / 0-day signals."}
          </li>
        )}
        {top.map((r) => (
          <li
            key={r.id}
            className="group flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-white/[0.03] transition"
          >
            <SeverityBadge severity={r.severity} />
            <span className="font-mono text-[11px] text-white truncate">{r.id}</span>
            {r.isZeroDay && (
              <span
                className="chip border-cyber-red/40 text-cyber-red bg-cyber-red/10 font-mono"
                title={`Zero-day score ${r.zeroDayScore}/100`}
              >
                <Flame className="w-3 h-3" /> {r.zeroDayScore}
              </span>
            )}
            {(r.pocs?.length ?? 0) > 0 && (
              <span className="chip border-cyber-purple/30 text-cyber-purple bg-cyber-purple/10 font-mono">
                <Github className="w-3 h-3" /> {r.pocs!.length}
              </span>
            )}
            <span className="text-[11px] text-slate-400 truncate flex-1 hidden md:inline">
              {describe(r)}
            </span>
            {(() => {
              const sig = whatChanged(r);
              if (!sig) return null;
              return (
                <span
                  className={`chip font-mono whitespace-nowrap ${SIGNAL_CLASSES[sig.tone]}`}
                  title={sig.title}
                >
                  {sig.label}
                </span>
              );
            })()}
            <span className="text-[10px] text-slate-500 font-mono">
              {timeAgo(r.modified)}
            </span>
          </li>
        ))}
      </ul>

      <Link
        to="/cves"
        className="mt-3 inline-flex items-center gap-1.5 text-[11px] font-mono text-cyber-cyan hover:underline"
      >
        Open full CVE explorer <ExternalLink className="w-3 h-3" />
      </Link>
    </Panel>
  );
}

function SignalBox({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  color: string;
}) {
  return (
    <div className={`rounded-xl border ${color} p-3`}>
      <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider">
        {icon} {label}
      </div>
      <div className="font-display text-2xl font-bold text-white mt-1">
        {value.toLocaleString()}
      </div>
    </div>
  );
}
