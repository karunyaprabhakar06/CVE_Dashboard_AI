import { motion } from "framer-motion";
import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface PanelProps {
  title?: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  headerClassName?: string;
  bodyClassName?: string;
  accent?: "cyan" | "purple" | "red" | "amber" | "green";
  delay?: number;
}

const accentMap: Record<string, string> = {
  cyan: "before:bg-cyber-cyan",
  purple: "before:bg-cyber-purple",
  red: "before:bg-cyber-red",
  amber: "before:bg-cyber-amber",
  green: "before:bg-cyber-green",
};

export default function Panel({
  title,
  subtitle,
  right,
  children,
  className,
  headerClassName,
  bodyClassName,
  accent = "cyan",
  delay = 0,
}: PanelProps) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className={cn(
        "glass glass-hover relative overflow-hidden group",
        "before:absolute before:left-0 before:top-0 before:h-full before:w-[2px] before:opacity-60",
        accentMap[accent],
        className
      )}
    >
      {(title || right) && (
        <header
          className={cn(
            "flex items-start justify-between gap-3 px-5 pt-4 pb-3",
            headerClassName
          )}
        >
          <div className="min-w-0">
            {title && (
              <h3 className="font-display text-sm font-semibold text-white tracking-wide truncate">
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="text-[11px] text-slate-500 mt-0.5 font-mono">
                {subtitle}
              </p>
            )}
          </div>
          {right && <div className="shrink-0">{right}</div>}
        </header>
      )}
      <div className={cn("px-5 pb-5", bodyClassName)}>{children}</div>
    </motion.section>
  );
}
