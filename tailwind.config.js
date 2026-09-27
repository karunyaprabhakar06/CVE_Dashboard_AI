/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: "#0B1020",
          panel: "#121826",
          elev: "#171F31",
          line: "#1F2A40",
        },
        cyber: {
          cyan: "#00D9FF",
          purple: "#7C3AED",
          red: "#EF4444",
          amber: "#F59E0B",
          green: "#10B981",
        },
      },
      fontFamily: {
        display: ["'Space Grotesk'", "system-ui", "sans-serif"],
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(0,217,255,0.25)",
        glowPurple: "0 0 24px rgba(124,58,237,0.30)",
        glowRed: "0 0 24px rgba(239,68,68,0.30)",
        panel:
          "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 0 0 1px rgba(255,255,255,0.04), 0 24px 60px -20px rgba(0,0,0,0.6)",
      },
      keyframes: {
        gridMove: {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "40px 40px" },
        },
        pulseRing: {
          "0%": { transform: "scale(0.8)", opacity: "0.6" },
          "100%": { transform: "scale(2)", opacity: "0" },
        },
        ticker: {
          "0%": { transform: "translateX(0)" },
          "100%": { transform: "translateX(-50%)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        float: {
          "0%,100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-6px)" },
        },
      },
      animation: {
        gridMove: "gridMove 6s linear infinite",
        pulseRing: "pulseRing 2.4s ease-out infinite",
        ticker: "ticker 60s linear infinite",
        shimmer: "shimmer 2.4s linear infinite",
        float: "float 4s ease-in-out infinite",
      },
      borderRadius: { xl2: "16px" },
    },
  },
  plugins: [],
};
