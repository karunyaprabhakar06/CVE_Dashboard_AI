import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, RotateCcw, Eye, EyeOff, LayoutDashboard } from "lucide-react";
import { WIDGET_REGISTRY, type WidgetId } from "@/lib/dashboardLayout";

interface Props {
  open: boolean;
  onClose: () => void;
  visible: Record<WidgetId, boolean>;
  onToggle: (id: WidgetId) => void;
  onSetAll: (value: boolean) => void;
  onReset: () => void;
}

const GROUP_LABELS: Record<string, string> = {
  overview: "Overview",
  vulns: "Vulnerabilities",
  intel: "Threat Intel",
};

export default function CustomizePanel({
  open,
  onClose,
  visible,
  onToggle,
  onSetAll,
  onReset,
}: Props) {
  // Close on Escape.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const grouped = WIDGET_REGISTRY.reduce<Record<string, typeof WIDGET_REGISTRY>>(
    (acc, w) => {
      (acc[w.group] ??= []).push(w);
      return acc;
    },
    {}
  );
  const visibleCount = Object.values(visible).filter(Boolean).length;

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <motion.div
            className="fixed right-0 top-0 z-50 h-full w-full max-w-md bg-[#0B1020] border-l border-white/10 shadow-2xl flex flex-col"
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", stiffness: 320, damping: 32 }}
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-white/10">
              <div className="flex items-center gap-2">
                <LayoutDashboard className="w-4 h-4 text-cyber-cyan" />
                <div>
                  <div className="text-white font-semibold text-sm">
                    Customize dashboard
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">
                    {visibleCount} of {WIDGET_REGISTRY.length} widgets visible
                  </div>
                </div>
              </div>
              <button
                onClick={onClose}
                className="w-8 h-8 rounded-md hover:bg-white/5 flex items-center justify-center text-slate-400 hover:text-white transition"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center gap-2 px-5 py-3 border-b border-white/5 text-[11px] font-mono">
              <button
                onClick={() => onSetAll(true)}
                className="px-2.5 h-7 rounded-md border border-white/10 text-slate-300 hover:text-white hover:border-cyber-cyan/50 transition flex items-center gap-1.5"
              >
                <Eye className="w-3 h-3" /> Show all
              </button>
              <button
                onClick={() => onSetAll(false)}
                className="px-2.5 h-7 rounded-md border border-white/10 text-slate-300 hover:text-white hover:border-cyber-amber/50 transition flex items-center gap-1.5"
              >
                <EyeOff className="w-3 h-3" /> Hide all
              </button>
              <button
                onClick={onReset}
                className="px-2.5 h-7 rounded-md border border-white/10 text-slate-300 hover:text-white hover:border-cyber-purple/50 transition flex items-center gap-1.5 ml-auto"
              >
                <RotateCcw className="w-3 h-3" /> Reset
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
              {Object.entries(grouped).map(([group, widgets]) => (
                <div key={group}>
                  <div className="text-[10px] uppercase tracking-widest font-mono text-slate-500 mb-2">
                    {GROUP_LABELS[group] ?? group}
                  </div>
                  <div className="space-y-1.5">
                    {widgets.map((w) => {
                      const on = visible[w.id];
                      return (
                        <button
                          key={w.id}
                          onClick={() => onToggle(w.id)}
                          className={
                            "w-full flex items-center gap-3 px-3 py-2 rounded-lg border transition text-left " +
                            (on
                              ? "border-cyber-cyan/40 bg-cyber-cyan/5 hover:bg-cyber-cyan/10"
                              : "border-white/10 bg-white/[0.02] hover:bg-white/[0.04]")
                          }
                        >
                          <div
                            className={
                              "w-9 h-5 rounded-full relative transition shrink-0 " +
                              (on ? "bg-cyber-cyan/80" : "bg-slate-700")
                            }
                          >
                            <div
                              className={
                                "absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all " +
                                (on ? "left-[18px]" : "left-0.5")
                              }
                            />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="text-[13px] text-white font-medium">
                              {w.label}
                            </div>
                            <div className="text-[11px] text-slate-500 truncate">
                              {w.description}
                            </div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>

            <div className="border-t border-white/10 px-5 py-3 text-[10.5px] font-mono text-slate-500">
              Preferences saved locally to your browser.
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
