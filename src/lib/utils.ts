import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(n: number) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return n.toString();
}

export function timeAgo(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export function severityFromCvss(score: number | null | undefined):
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "NONE" {
  if (score == null) return "NONE";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#EF4444",
  HIGH: "#F59E0B",
  MEDIUM: "#00D9FF",
  LOW: "#10B981",
  NONE: "#64748B",
};

export const SEVERITY_BG: Record<string, string> = {
  CRITICAL: "bg-cyber-red/15 text-cyber-red border-cyber-red/30",
  HIGH: "bg-cyber-amber/15 text-cyber-amber border-cyber-amber/30",
  MEDIUM: "bg-cyber-cyan/15 text-cyber-cyan border-cyber-cyan/30",
  LOW: "bg-cyber-green/15 text-cyber-green border-cyber-green/30",
  NONE: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};
