import { type ReactNode } from "react";
import { AnimatePresence } from "framer-motion";
import Sidebar from "./Sidebar";
import TopBar from "./TopBar";
import GridOverlay from "./GridOverlay";
import { useStore } from "@/lib/store";
import { DetailDrawer } from "@/pages/CVEs";

export default function Shell({ children }: { children: ReactNode }) {
  const focusedCve = useStore((s) => s.focusedCve);
  const closeCve = useStore((s) => s.closeCve);
  return (
    <div className="relative min-h-screen">
      <GridOverlay />
      <div className="relative z-10 flex min-h-screen">
        <Sidebar />
        <div className="relative z-20 flex-1 flex flex-col min-w-0">
          <TopBar />
          <main className="flex-1 p-4 md:p-6 max-w-[1800px] w-full mx-auto">
            {children}
          </main>
          <footer className="px-6 py-4 text-[11px] text-slate-500 flex items-center justify-between border-t border-white/5">
            <span className="font-mono">
              CTI v0.1 · NVD · OSV · CISA KEV · GitHub PoCs · trickest · Exploit-DB · Nuclei templates · FIRST EPSS
            </span>
            <span className="font-mono">
              © {new Date().getFullYear()} Cyber Defense Operations
            </span>
          </footer>
        </div>
      </div>
      <AnimatePresence>
        {focusedCve && (
          <DetailDrawer record={focusedCve} onClose={closeCve} />
        )}
      </AnimatePresence>
    </div>
  );
}
