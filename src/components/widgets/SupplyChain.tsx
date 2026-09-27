// Supply-chain / kernel CVE correlation panel.
//
// Parents: Linux-kernel CVEs published in the last 7 days (vendor=linux or
//          product contains "kernel"/"linux_kernel").
// Children: any other CVE record whose description or references mention the
//           parent CVE id — typically distro rebroadcasts (RHSA, USN, SUSE-SU,
//           Debian DSA, Oracle ELSA, Amazon ALAS, Alpine, Fedora …) plus
//           container-image / cloud-vendor advisories that pin to the
//           upstream kernel CVE.
import { useMemo, useState } from "react";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";
import { SeverityBadge } from "../ui/SeverityBadge";
import {
  ChevronRight,
  GitBranch,
  Boxes,
  Cpu,
  ExternalLink,
} from "lucide-react";
import { timeAgo } from "@/lib/utils";
import type { CVERecord } from "@/lib/types";

const WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

// Heuristic: which vendor strings indicate "upstream Linux kernel" (parent)
// vs "downstream distro / cloud / container vendor" (child).
const KERNEL_VENDORS = new Set([
  "linux",
  "kernel.org",
  "kernelorg",
  "torvalds",
]);

const DISTRO_VENDORS = new Set([
  "redhat",
  "red_hat",
  "rhel",
  "centos",
  "rocky",
  "almalinux",
  "fedora",
  "fedoraproject",
  "canonical",
  "ubuntu",
  "debian",
  "suse",
  "opensuse",
  "oracle",
  "amazon",
  "amazonlinux",
  "alpine",
  "alpinelinux",
  "google",
  "microsoft",
  "vmware",
  "docker",
]);

function isKernelParent(r: CVERecord): boolean {
  const v = (r.vendor ?? "").toLowerCase();
  const p = (r.product ?? "").toLowerCase();
  if (KERNEL_VENDORS.has(v) && p.includes("kernel")) return true;
  if (v === "linux" && (p === "" || p === "linux" || p.includes("kernel")))
    return true;
  if (p === "linux_kernel") return true;
  return false;
}

function originLabel(r: CVERecord): string {
  const v = (r.vendor ?? "").toLowerCase();
  if (DISTRO_VENDORS.has(v)) return r.vendor!;
  if (v.includes("redhat")) return "RedHat";
  if (v.includes("ubuntu") || v.includes("canonical")) return "Ubuntu";
  if (v.includes("suse")) return "SUSE";
  if (v.includes("debian")) return "Debian";
  if (v.includes("oracle")) return "Oracle";
  if (v.includes("amazon")) return "Amazon";
  return r.vendor ?? r.source ?? "other";
}

export default function SupplyChain() {
  const records = useStore((s) => s.records);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const { parents, totalChildren } = useMemo(() => {
    const cutoff = Date.now() - WINDOW_MS;

    // Pass 1: index every CVE-id mentioned by every other record.
    // mentioned[parentId] -> children[] (excluding the parent itself).
    const mentioned = new Map<string, CVERecord[]>();
    for (const r of records) {
      const haystack =
        (r.description ?? "") + " " + (r.references ?? []).join(" ");
      const ids = new Set<string>();
      const matches = haystack.match(CVE_RE);
      if (!matches) continue;
      for (const m of matches) {
        const id = m.toUpperCase();
        if (id === r.id) continue;
        ids.add(id);
      }
      for (const id of ids) {
        const list = mentioned.get(id);
        if (list) list.push(r);
        else mentioned.set(id, [r]);
      }
    }

    // Pass 2: pick kernel parents within the 7-day window, attach children.
    // Use the most-recent of published/modified — kernel.org tends to publish
    // in irregular batches but downstream activity (NVD enrichment, KEV
    // backports, distro rebroadcasts) keeps the `modified` timestamp live.
    const recencyOf = (r: CVERecord) =>
      Math.max(
        Date.parse(r.modified ?? "") || 0,
        Date.parse(r.published ?? "") || 0
      );
    const candidates = records
      .filter(isKernelParent)
      .filter((r) => recencyOf(r) >= cutoff);

    const rows = candidates
      .map((p) => {
        const kids = (mentioned.get(p.id) ?? []).sort(
          (a, b) =>
            Date.parse(b.modified ?? b.published ?? "0") -
            Date.parse(a.modified ?? a.published ?? "0")
        );
        return { parent: p, children: kids };
      })
      // Most "supply-chain-relevant" first: most children, then severity, then newest.
      .sort((a, b) => {
        if (b.children.length !== a.children.length)
          return b.children.length - a.children.length;
        const cv = (b.parent.cvss ?? 0) - (a.parent.cvss ?? 0);
        if (cv !== 0) return cv;
        return recencyOf(b.parent) - recencyOf(a.parent);
      })
      .slice(0, 12);

    return {
      parents: rows,
      totalChildren: rows.reduce((n, r) => n + r.children.length, 0),
    };
  }, [records]);

  const toggle = (id: string) =>
    setExpanded((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  return (
    <Panel
      title="Supply-Chain · Kernel CVEs"
      subtitle="Upstream Linux-kernel CVEs (last 7d) → downstream distro / vendor children"
      accent="purple"
      delay={0.24}
      right={
        <div className="flex items-center gap-2">
          <div className="chip border-cyber-purple/30 text-cyber-purple bg-cyber-purple/10 font-mono">
            <Cpu className="w-3 h-3" /> {parents.length} parent
          </div>
          <div className="chip border-cyber-cyan/30 text-cyber-cyan bg-cyber-cyan/10 font-mono">
            <Boxes className="w-3 h-3" /> {totalChildren} children
          </div>
        </div>
      }
    >
      {parents.length === 0 ? (
        <div className="text-[12px] font-mono text-slate-500 py-8 text-center">
          No kernel-tagged CVEs in the last 7 days. Check back after the next
          NVD refresh — kernel.org typically publishes weekly batches.
        </div>
      ) : (
        <ul className="space-y-1.5 max-h-[420px] overflow-auto pr-1">
          {parents.map(({ parent, children }) => {
            const open = expanded.has(parent.id);
            return (
              <li
                key={parent.id}
                className="rounded-lg border border-white/5 bg-white/[0.02]"
              >
                <button
                  onClick={() => toggle(parent.id)}
                  className="w-full flex items-center gap-2 px-2.5 py-2 text-left hover:bg-white/[0.03] transition rounded-lg"
                >
                  <ChevronRight
                    className={`w-3.5 h-3.5 text-slate-500 transition-transform ${
                      open ? "rotate-90" : ""
                    }`}
                  />
                  <GitBranch className="w-3.5 h-3.5 text-cyber-purple shrink-0" />
                  <SeverityBadge severity={parent.severity} />
                  <span className="font-mono text-[11px] text-white shrink-0">
                    {parent.id}
                  </span>
                  {parent.cvss != null && (
                    <span className="chip border-cyber-amber/30 text-cyber-amber bg-cyber-amber/10 font-mono">
                      {parent.cvss.toFixed(1)}
                    </span>
                  )}
                  <span className="text-[11px] text-slate-400 truncate flex-1 hidden md:inline">
                    {parent.description?.slice(0, 80)}
                  </span>
                  <span className="chip border-cyber-cyan/30 text-cyber-cyan bg-cyber-cyan/10 font-mono shrink-0">
                    <Boxes className="w-3 h-3" /> {children.length}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono shrink-0">
                    {timeAgo(parent.modified ?? parent.published)}
                  </span>
                </button>
                {open && (
                  <div className="px-2.5 pb-2 pl-9 space-y-1">
                    {children.length === 0 ? (
                      <div className="text-[11px] font-mono text-slate-500 py-1.5">
                        No downstream advisories indexed yet — distro rebroadcasts
                        typically follow within 24–72h.
                      </div>
                    ) : (
                      children.slice(0, 20).map((c) => (
                        <div
                          key={c.id}
                          className="flex items-center gap-2 text-[11px] py-1"
                        >
                          <span className="w-1 h-1 rounded-full bg-cyber-purple/60 shrink-0" />
                          <SeverityBadge severity={c.severity} />
                          <span className="font-mono text-white shrink-0">
                            {c.id}
                          </span>
                          <span className="chip border-white/10 text-slate-300 bg-white/5 font-mono shrink-0">
                            {originLabel(c)}
                          </span>
                          <span className="text-slate-400 truncate flex-1">
                            {c.description?.slice(0, 70)}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono shrink-0">
                            {timeAgo(c.modified ?? c.published)}
                          </span>
                        </div>
                      ))
                    )}
                    {parent.references && parent.references.length > 0 && (
                      <a
                        href={parent.references[0]}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-[10px] font-mono text-cyber-cyan hover:underline pt-1"
                      >
                        upstream reference <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
