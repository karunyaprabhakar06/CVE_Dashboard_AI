// Linux distribution CVE breakdown (last 30 days).
// X-axis: distro (Debian, Ubuntu, CentOS, RHEL, Fedora, SUSE, Arch, Alpine, …)
// Y-axis: count of CVEs, stacked by severity (CRITICAL / HIGH / MEDIUM / LOW).
// Side panel: kernel-vs-services split for each distro.
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import Panel from "../ui/Panel";
import { useStore } from "@/lib/store";
import { SEVERITY_COLORS } from "@/lib/utils";
import type { CVERecord, Severity } from "@/lib/types";
import { Server } from "lucide-react";

type Slice = "all" | "kernel" | "services";

interface DistroDef {
  key: string;
  label: string;
  match: RegExp;
}

// Order roughly by typical enterprise prevalence. The trailing "generic"
// bucket catches every Linux-related CVE that doesn't name a specific distro
// — keeps the chart's totals consistent with the CVE page's "Linux Infra"
// filter (category ∈ {linux-kernel, linux-service, container}).
const DISTROS: DistroDef[] = [
  { key: "debian", label: "Debian", match: /\bdebian\b/i },
  { key: "ubuntu", label: "Ubuntu", match: /\bubuntu\b|\bcanonical\b/i },
  { key: "rhel", label: "RHEL", match: /\brhel\b|red[\s-]?hat enterprise|\bredhat\b/i },
  { key: "centos", label: "CentOS", match: /\bcentos\b/i },
  { key: "fedora", label: "Fedora", match: /\bfedora\b/i },
  { key: "suse", label: "SUSE", match: /\bsuse\b|opensuse|sles\b/i },
  { key: "alpine", label: "Alpine", match: /\balpine\b/i },
  { key: "arch", label: "Arch", match: /\barch[\s-]?linux\b|\barchlinux\b/i },
  { key: "amazon", label: "Amazon", match: /\bamazon[\s-]?linux\b|\bamzn\b/i },
  { key: "oracle", label: "Oracle", match: /\boracle[\s-]?linux\b/i },
  // Synthetic catch-all for Linux records without a named distro.
  { key: "generic", label: "Generic Linux", match: /^\b\B$/ },
];

const KERNEL_RX = /\blinux[\s-]?kernel\b|\bkernel\b/i;

// Treat a record as Linux-related if either its category is one of the Linux
// buckets used by the CVE page's "Linux Infra" filter, or its text mentions
// Linux explicitly. Anything that classifyDistro can't tag with a specific
// distro falls through to the "generic" bucket so the chart's totals stay
// honest.
const LINUX_CATEGORIES = new Set(["linux-kernel", "linux-service", "container"]);
function isLinuxRecord(r: CVERecord): boolean {
  if (LINUX_CATEGORIES.has(r.category ?? "")) return true;
  const blob = `${r.vendor ?? ""} ${r.product ?? ""} ${r.description ?? ""}`;
  return /\blinux\b/i.test(blob);
}

function classifyDistro(r: CVERecord): string | null {
  const blob = `${r.vendor ?? ""} ${r.product ?? ""} ${r.description ?? ""}`;
  for (const d of DISTROS) {
    if (d.key === "generic") continue;
    if (d.match.test(blob)) return d.key;
  }
  return isLinuxRecord(r) ? "generic" : null;
}

// Two layers only: Linux kernel itself vs. Services — everything else that
// runs on top of it (daemons, web servers, language runtimes, frameworks,
// libraries, browsers, container tooling).
function classifyLayer(r: CVERecord): "kernel" | "services" {
  const cat = r.category ?? "";
  if (cat === "linux-kernel") return "kernel";
  const blob = `${r.product ?? ""} ${r.description ?? ""}`;
  if (KERNEL_RX.test(blob)) return "kernel";
  return "services";
}

// Derive a clean, human-readable service/component name from a CVE record.
// Prefers the explicit product field; falls back to scanning the description
// for known userspace components so we never show empty labels in the
// drill-down tooltip.
const SERVICE_PATTERNS: Array<[RegExp, string]> = [
  [/\bopenssh\b|\bsshd\b/i, "OpenSSH"],
  [/\bnginx\b/i, "nginx"],
  [/\bapache(?:\s+http)?\b|\bhttpd\b/i, "Apache HTTPD"],
  [/\bsystemd\b/i, "systemd"],
  [/\bopenssl\b/i, "OpenSSL"],
  [/\bglibc\b|\bgnu c library\b/i, "glibc"],
  [/\bsudo\b/i, "sudo"],
  [/\bpolkit\b/i, "polkit"],
  [/\bsamba\b/i, "Samba"],
  [/\bbind\b/i, "BIND"],
  [/\bpostgres(?:ql)?\b/i, "PostgreSQL"],
  [/\bmariadb\b/i, "MariaDB"],
  [/\bmysql\b/i, "MySQL"],
  [/\bredis\b/i, "Redis"],
  [/\bdocker\b/i, "Docker"],
  [/\bcontainerd\b/i, "containerd"],
  [/\bpodman\b/i, "Podman"],
  [/\bqemu\b/i, "QEMU"],
  [/\blibvirt\b/i, "libvirt"],
  [/\bcurl\b/i, "curl"],
  [/\bwget\b/i, "wget"],
  [/\bgit\b/i, "git"],
  [/\bpython\b/i, "Python"],
  [/\bnode(?:\.?js)?\b/i, "Node.js"],
  [/\bphp\b/i, "PHP"],
  [/\bruby\b/i, "Ruby"],
  [/\bperl\b/i, "Perl"],
  [/\bgo(?:lang)?\b/i, "Go"],
  [/\brust\b/i, "Rust"],
  [/\bfirefox\b/i, "Firefox"],
  [/\bchrom(?:e|ium)\b/i, "Chromium"],
  [/\bthunderbird\b/i, "Thunderbird"],
  [/\bgnutls\b/i, "GnuTLS"],
  [/\bzlib\b/i, "zlib"],
  [/\blibxml2?\b/i, "libxml2"],
  [/\bffmpeg\b/i, "FFmpeg"],
  [/\bimagemagick\b/i, "ImageMagick"],
  [/\bcups\b/i, "CUPS"],
  [/\bnetworkmanager\b/i, "NetworkManager"],
  [/\bgrub2?\b/i, "GRUB"],
];

function serviceLabel(r: CVERecord): string {
  const product = (r.product ?? "").trim();
  if (product && product.toLowerCase() !== "n/a") {
    // Normalise common product-name noise: strip vendor prefix, trim version.
    const clean = product.replace(/\s+\d+(\.\d+)*$/, "").trim();
    if (clean.length > 1 && clean.length <= 40) return clean;
  }
  const desc = r.description ?? "";
  for (const [rx, label] of SERVICE_PATTERNS) if (rx.test(desc)) return label;
  return "Other / unspecified";
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
type SevKey = (typeof SEVERITIES)[number];

// Stable color per distro (ordered to match DISTROS rough enterprise prevalence).
const DISTRO_COLORS = [
  "#A78BFA", // purple — Debian
  "#F97316", // orange — Ubuntu
  "#EF4444", // red — RHEL
  "#22D3EE", // cyan — CentOS
  "#3B82F6", // blue — Fedora
  "#10B981", // green — SUSE
  "#94A3B8", // slate — Alpine
  "#F59E0B", // amber — Arch
  "#EC4899", // pink — Amazon
  "#8B5CF6", // violet — Oracle
  "#64748B", // slate-600 — Generic Linux (catch-all)
];

export default function DistroCVEs() {
  const records = useStore((s) => s.records);
  const navigate = useNavigate();
  const [slice, setSlice] = useState<Slice>("all");

  // Jump to the CVE list filtered to the clicked context.
  function drillTo(opts: { severity?: SevKey; linuxOnly?: boolean } = {}) {
    const params = new URLSearchParams();
    if (opts.severity) params.set("severity", opts.severity);
    if (opts.linuxOnly ?? true) params.set("linuxOnly", "1");
    if (slice === "services") params.set("category", "linux-service");
    if (slice === "kernel") params.set("category", "linux-kernel");
    // The chart aggregates the last 30 days off whichever timestamp is
    // newer (modified || published) — mirror that on the CVE page so the
    // user actually sees the rows that drove the bar they clicked.
    params.set("range", "1mo");
    params.set("basis", "modified");
    navigate(`/cves?${params.toString()}`);
  }

  const { data, sevRows, distroOrder, serviceTree, layerTotals } = useMemo(() => {
    const cutoff = Date.now() - 30 * 86_400_000;
    const buckets = new Map<string, Record<SevKey, number>>();
    const layerBuckets = new Map<string, { kernel: number; services: number }>();
    // severity → service/product label → count (for the deep-dive tooltip).
    const svcTree: Record<SevKey, Record<string, number>> = {
      CRITICAL: {},
      HIGH: {},
      MEDIUM: {},
      LOW: {},
    };
    for (const d of DISTROS) {
      buckets.set(d.key, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
      layerBuckets.set(d.key, { kernel: 0, services: 0 });
    }
    let kernelT = 0,
      svcT = 0;
    for (const r of records) {
      const t = new Date(r.published || r.modified).getTime();
      if (!t || t < cutoff) continue;
      const distro = classifyDistro(r);
      if (!distro) continue;
      const layer = classifyLayer(r);
      if (slice === "kernel" && layer !== "kernel") continue;
      if (slice === "services" && layer !== "services") continue;
      const sev = r.severity as Severity;
      if (sev === "NONE") continue;
      const b = buckets.get(distro)!;
      b[sev as SevKey] += 1;
      const lb = layerBuckets.get(distro)!;
      lb[layer] += 1;
      if (layer === "kernel") kernelT++;
      else svcT++;
      // Deep-dive: bucket by product/service name (skip kernel itself — we
      // want to highlight the affected userspace components).
      if (layer === "services") {
        const svcLabel = serviceLabel(r);
        svcTree[sev as SevKey][svcLabel] = (svcTree[sev as SevKey][svcLabel] ?? 0) + 1;
      }
    }
    const rows = DISTROS.map((d) => {
      const b = buckets.get(d.key)!;
      return {
        distro: d.label,
        key: d.key,
        CRITICAL: b.CRITICAL,
        HIGH: b.HIGH,
        MEDIUM: b.MEDIUM,
        LOW: b.LOW,
        total: b.CRITICAL + b.HIGH + b.MEDIUM + b.LOW,
        kernel: layerBuckets.get(d.key)!.kernel,
        services: layerBuckets.get(d.key)!.services,
      };
    })
      .filter((r) => r.total > 0)
      .sort((a, b) => b.total - a.total);

    // Pivot into severity-keyed rows (one bar per severity, stacked by distro).
    const sevRows = SEVERITIES.map((sev) => {
      const row: Record<string, string | number> = { severity: sev };
      for (const r of rows) row[r.distro] = r[sev];
      return row;
    });
    const distroOrder = rows.map((r) => r.distro);

    return {
      data: rows,
      sevRows,
      distroOrder,
      serviceTree: svcTree,
      layerTotals: { kernel: kernelT, services: svcT },
    };
  }, [records, slice]);

  const grandTotal = layerTotals.kernel + layerTotals.services;

  return (
    <Panel
      title="Linux Distribution CVEs"
      subtitle={`Last 30 days · ${grandTotal.toLocaleString()} CVEs across ${data.length} distros`}
      accent="purple"
      delay={0.18}
      right={
        <div className="flex items-center gap-1.5">
          {(["all", "services"] as Slice[]).map((s) => (
            <button
              key={s}
              onClick={() => setSlice(s)}
              className={
                "h-7 px-2.5 rounded-md text-[10.5px] font-mono uppercase tracking-wider border transition flex items-center gap-1.5 " +
                (slice === s
                  ? "border-cyber-purple/60 text-cyber-purple bg-cyber-purple/15"
                  : "border-white/10 text-slate-400 hover:text-white hover:border-white/30")
              }
            >
              {s === "services" ? <Server className="w-3 h-3" /> : null}
              {s === "all" ? "All" : "Services"}
            </button>
          ))}
        </div>
      }
    >
      {data.length === 0 ? (
        <div className="text-[12.5px] text-slate-500 font-mono py-10 text-center">
          No distro-attributed CVEs in the last 30 days for this slice.
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_240px] gap-5">
          <div className="h-[280px]">
            <ResponsiveContainer>
              <BarChart
                data={sevRows}
                margin={{ top: 10, right: 8, left: -16, bottom: 0 }}
              >
                <CartesianGrid stroke="#1F2A40" strokeDasharray="3 6" vertical={false} />
                <XAxis
                  dataKey="severity"
                  stroke="#475569"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  tick={({ x, y, payload }) => (
                    <text
                      x={x}
                      y={y + 14}
                      textAnchor="middle"
                      fontSize={11}
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                      fill={SEVERITY_COLORS[payload.value as Severity] ?? "#94A3B8"}
                    >
                      {payload.value}
                    </text>
                  )}
                />
                <YAxis stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip
                  cursor={{ fill: "rgba(255,255,255,0.04)" }}
                  content={({ active, label }) => {
                    if (!active || !label) return null;
                    const sev = String(label) as SevKey;
                    const node = serviceTree[sev] ?? {};
                    const entries = Object.entries(node)
                      .map(([service, count]) => ({ service, count }))
                      .filter((e) => e.count > 0)
                      .sort((a, b) => b.count - a.count);
                    const totalSev = entries.reduce((s, e) => s + e.count, 0);
                    const sevColor = SEVERITY_COLORS[sev] ?? "#94A3B8";
                    const TOP = 12;
                    const top = entries.slice(0, TOP);
                    const restCount = entries.slice(TOP).reduce((s, e) => s + e.count, 0);
                    return (
                      <div
                        style={{
                          background: "#0B1020",
                          border: `1px solid ${sevColor}55`,
                          borderRadius: 12,
                          padding: "10px 12px",
                          fontSize: 12,
                          color: "#E2E8F0",
                          minWidth: 240,
                          maxWidth: 320,
                          boxShadow: "0 4px 18px rgba(0,0,0,0.45)",
                        }}
                      >
                        <div
                          style={{
                            color: sevColor,
                            fontFamily: "monospace",
                            fontSize: 10,
                            letterSpacing: "0.12em",
                            textTransform: "uppercase",
                            marginBottom: 6,
                          }}
                        >
                          {sev} · {totalSev} affected service
                          {totalSev === 1 ? "" : "s"}
                        </div>
                        {entries.length === 0 ? (
                          <div style={{ color: "#64748B", fontStyle: "italic" }}>
                            no records
                          </div>
                        ) : (
                          <div
                            style={{ display: "flex", flexDirection: "column", gap: 3 }}
                          >
                            {top.map((e, idx) => {
                              const isLast =
                                idx === top.length - 1 && restCount === 0;
                              return (
                                <div
                                  key={e.service}
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "space-between",
                                    gap: 8,
                                    fontFamily: "monospace",
                                    fontSize: 11.5,
                                    lineHeight: 1.5,
                                  }}
                                >
                                  <span style={{ color: "#CBD5E1" }}>
                                    {isLast ? "└─" : "├─"} {e.service}
                                  </span>
                                  <span style={{ color: sevColor }}>{e.count}</span>
                                </div>
                              );
                            })}
                            {restCount > 0 && (
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  color: "#64748B",
                                  fontFamily: "monospace",
                                  fontSize: 11.5,
                                  lineHeight: 1.5,
                                }}
                              >
                                <span>└─ +{entries.length - TOP} more</span>
                                <span>{restCount}</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  }}
                />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  wrapperStyle={{ fontSize: 11, color: "#94A3B8" }}
                />
                {distroOrder.map((distro, i) => (
                  <Bar
                    key={distro}
                    dataKey={distro}
                    stackId="distro"
                    fill={DISTRO_COLORS[i % DISTRO_COLORS.length]}
                    radius={
                      i === distroOrder.length - 1
                        ? [4, 4, 0, 0]
                        : i === 0
                        ? [0, 0, 4, 4]
                        : 0
                    }
                    maxBarSize={48}
                    cursor="pointer"
                    onClick={(p) => {
                      const sev = (p && (p as { severity?: SevKey }).severity) ||
                        (p && (p as { payload?: { severity?: SevKey } }).payload?.severity);
                      if (sev) drillTo({ severity: sev });
                    }}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-2">
            <button
              type="button"
              onClick={() => drillTo()}
              className="w-full text-left text-[10px] uppercase tracking-widest font-mono text-slate-500 hover:text-cyber-cyan transition mb-1"
              title="Open the full CVE list with these filters"
            >
              Affected services (last 30d) ↗
            </button>
            <button
              type="button"
              onClick={() => drillTo()}
              className="w-full text-left"
            >
              <SidebarRow
                icon={<Server className="w-3 h-3" />}
                label="Services / userspace"
                value={layerTotals.services}
                color="#00D9FF"
              />
            </button>
            <div className="mt-3 text-[10.5px] text-slate-500 leading-relaxed font-mono">
              Daemons, language runtimes, frameworks, libraries, tooling and browsers
              reported in the last 30 days. Click any bar to open the full list.
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}

function SidebarRow({
  icon,
  label,
  value,
  color,
}: {
  icon?: React.ReactNode;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-md bg-white/[0.02] border border-white/5">
      <div className="flex items-center gap-1.5 text-[11px] font-mono" style={{ color }}>
        {icon}
        <span>{label}</span>
      </div>
      <div className="font-display text-sm text-white tabular-nums">
        {value.toLocaleString()}
      </div>
    </div>
  );
}
