import { Route, Routes, Navigate, Outlet, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import Shell from "./components/layout/Shell";
import Dashboard from "./pages/Dashboard";
import CVEs from "./pages/CVEs";
import Login from "./pages/Login";
import { useStore } from "./lib/store";
import { getSession } from "./lib/auth";

function ProtectedLayout() {
  const navigate = useNavigate();
  const start = useStore((s) => s.startAutoRefresh);
  const stop = useStore((s) => s.stopAutoRefresh);

  const session = getSession();

  useEffect(() => {
    if (!session) return;
    start();
    return () => stop();
  }, [start, stop]);

  // Redirect to login if session expires while the tab is open
  useEffect(() => {
    const id = window.setInterval(() => {
      if (!getSession()) navigate("/login", { replace: true });
    }, 60_000);
    return () => window.clearInterval(id);
  }, [navigate]);

  if (!session) return <Navigate to="/login" replace />;

  return (
    <Shell>
      <Outlet />
    </Shell>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedLayout />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/cves" element={<CVEs />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}
