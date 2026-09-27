import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    proxy: {
      "/api/auth": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
      "/api/feed": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
      "/api/health": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
      "/api/search": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
      "/api/ai": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
      "/api/nvd": {
        target: "https://services.nvd.nist.gov",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api\/nvd/, ""),
      },
      "/api/osv": {
        target: "https://api.osv.dev",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api\/osv/, ""),
      },
      "/api/kev": {
        target: "https://www.cisa.gov",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api\/kev/, ""),
      },
    },
  },
});
