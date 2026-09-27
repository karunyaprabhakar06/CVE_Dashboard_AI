import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Lock,
  Eye,
  EyeOff,
  AlertTriangle,
  Loader2,
  User,
} from "lucide-react";
import { saveSession } from "@/lib/auth";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Authentication failed");
        return;
      }
      saveSession(data.token, data.username, data.expiresAt);
      navigate("/dashboard", { replace: true });
    } catch {
      setError("Backend unreachable. Ensure the server is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Animated grid background */}
      <div
        className="absolute inset-0 opacity-[0.035] pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,217,255,0.9) 1px, transparent 1px), linear-gradient(90deg, rgba(0,217,255,0.9) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
          animation: "gridMove 6s linear infinite",
        }}
      />

      {/* Ambient glow blobs */}
      <div className="absolute top-[-10%] left-[15%] w-[500px] h-[500px] bg-cyber-purple/15 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[10%] w-[500px] h-[500px] bg-cyber-cyan/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute top-[40%] left-[60%] w-[300px] h-[300px] bg-cyber-purple/10 rounded-full blur-[80px] pointer-events-none" />

      <div className="relative z-10 w-full max-w-sm mx-4 flex flex-col items-center gap-5">
        {/* Platform badge */}
        <div className="flex items-center gap-2 px-4 py-1.5 rounded-full border border-cyber-cyan/30 bg-cyber-cyan/5 backdrop-blur-sm">
          <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
          <span className="text-[10px] font-mono text-cyber-cyan uppercase tracking-[0.18em]">
            CVE Threat Intelligence Platform
          </span>
        </div>

        {/* Card */}
        <div className="w-full rounded-2xl border border-white/10 bg-bg-panel/80 backdrop-blur-2xl shadow-panel p-8 flex flex-col gap-6">
          {/* Shield icon */}
          <div className="flex flex-col items-center gap-3">
            <div className="relative flex items-center justify-center">
              <div className="absolute w-20 h-20 rounded-2xl bg-cyber-cyan/10 blur-xl" />
              <div className="relative w-16 h-16 rounded-2xl bg-gradient-to-br from-cyber-cyan/20 to-cyber-purple/25 border border-cyber-cyan/30 flex items-center justify-center shadow-glow">
                <Shield className="w-8 h-8 text-cyber-cyan" />
              </div>
            </div>
            <div className="text-center">
              <h1 className="font-display font-bold text-white text-[1.25rem] leading-tight">
                Secure Access
              </h1>
              <p className="text-[11px] font-mono text-slate-500 mt-0.5 uppercase tracking-widest">
                Authenticate to access the dashboard
              </p>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={onSubmit} className="flex flex-col gap-4">
            {/* Username */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase tracking-widest text-slate-400">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  required
                  placeholder="analyst"
                  className="w-full h-10 pl-9 pr-3 rounded-xl bg-bg-elev/70 border border-white/10 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyber-cyan/50 focus:shadow-glow transition font-mono"
                />
              </div>
            </div>

            {/* Password */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase tracking-widest text-slate-400">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
                <input
                  type={showPw ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                  placeholder="••••••••"
                  className="w-full h-10 pl-9 pr-10 rounded-xl bg-bg-elev/70 border border-white/10 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyber-cyan/50 focus:shadow-glow transition font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
                  tabIndex={-1}
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error message */}
            {error && (
              <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl border border-cyber-red/30 bg-cyber-red/10 text-cyber-red text-[12px] font-mono">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || !username.trim() || !password}
              className="w-full h-11 mt-1 rounded-xl bg-gradient-to-r from-cyber-cyan/15 to-cyber-purple/15 border border-cyber-cyan/40 hover:border-cyber-cyan/70 hover:from-cyber-cyan/25 hover:to-cyber-purple/25 text-cyber-cyan font-mono text-[13px] font-semibold uppercase tracking-widest transition hover:shadow-glow disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Authenticating…
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  Access Terminal
                </>
              )}
            </button>
          </form>
        </div>

        {/* Footer note */}
        <div className="flex flex-col items-center gap-1">
          <p className="text-[10px] font-mono text-slate-600 text-center">
            Session expires after{" "}
            <span className="text-slate-500">48 hours</span>
            {" · "}Auto-logout on timeout
          </p>
          <p className="text-[10px] font-mono text-slate-700 text-center">
            CTI · NVD · CISA KEV · GitHub PoCs · EPSS
          </p>
        </div>
      </div>
    </div>
  );
}
