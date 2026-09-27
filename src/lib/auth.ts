const SESSION_KEY = "cve-auth-session";
const SESSION_TTL_MS = 2 * 24 * 60 * 60 * 1000; // 48 hours

export interface AuthSession {
  token: string;
  expiresAt: number;
  username: string;
}

export function getSession(): AuthSession | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const session = JSON.parse(raw) as AuthSession;
    if (Date.now() >= session.expiresAt) {
      localStorage.removeItem(SESSION_KEY);
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

export function saveSession(token: string, username: string, expiresAt: number): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify({ token, expiresAt, username } satisfies AuthSession));
}

export function clearSession(): void {
  localStorage.removeItem(SESSION_KEY);
}

export function getAuthHeaders(): Record<string, string> {
  const session = getSession();
  return session ? { Authorization: `Bearer ${session.token}` } : {};
}

export async function logout(): Promise<void> {
  const session = getSession();
  clearSession();
  if (session) {
    await fetch("/api/auth/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${session.token}` },
    }).catch(() => {});
  }
}

export function sessionExpiresIn(): string {
  const session = getSession();
  if (!session) return "expired";
  const msLeft = session.expiresAt - Date.now();
  const hoursLeft = Math.floor(msLeft / (60 * 60 * 1000));
  if (hoursLeft >= 24) return `${Math.floor(hoursLeft / 24)}d ${hoursLeft % 24}h`;
  if (hoursLeft >= 1) return `${hoursLeft}h`;
  const minsLeft = Math.floor(msLeft / 60_000);
  return `${minsLeft}m`;
}
