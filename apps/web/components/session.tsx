"use client";

import * as React from "react";
import { api, type Me, setCsrf } from "@/lib/api";

const SessionContext = React.createContext<{ me: Me | null; can: (p: string) => boolean }>({
  me: null, can: () => false,
});

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = React.useState<Me | null>(null);
  const [failed, setFailed] = React.useState(false);
  React.useEffect(() => {
    api<Me>("/auth/me").then((m) => { setCsrf(m.csrf_token); setMe(m); })
      .catch(() => { setFailed(true); window.location.href = "/login"; });
  }, []);
  const can = React.useCallback((p: string) => Boolean(me?.permissions.includes(p)), [me]);
  if (!me) {
    return <div className="p-10 text-sm text-muted">{failed ? "Redirecting to sign-in…" : "Loading…"}</div>;
  }
  return <SessionContext.Provider value={{ me, can }}>{children}</SessionContext.Provider>;
}

export function useSession() {
  return React.useContext(SessionContext);
}

/** Hides UI the user cannot use. This is UX only — every request is authorized server-side. */
export function Can({ perm, children }: { perm: string; children: React.ReactNode }) {
  const { can } = useSession();
  return can(perm) ? <>{children}</> : null;
}
