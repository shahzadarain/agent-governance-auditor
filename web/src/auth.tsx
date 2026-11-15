// SPDX-License-Identifier: Apache-2.0

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, ApiError, setCsrfToken, setUnauthorizedHandler } from "./api/client";
import type { Session, User, VersionInfo } from "./api/types";
import { clearScanCache } from "./lib/data";

export type AuthPhase = "loading" | "setup" | "anonymous" | "signed-in" | "error";

interface AuthValue {
  phase: AuthPhase;
  user: User | null;
  version: VersionInfo | null;
  error: ApiError | null;
  /** True when the last session ended because the server answered 401. */
  expired: boolean;
  isAdmin: boolean;
  signIn: (s: Session) => void;
  signOut: () => Promise<void>;
  /** Call after first-run setup succeeds. */
  setupDone: () => void;
  retry: () => void;
}

const Ctx = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<AuthPhase>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [expired, setExpired] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const ctl = new AbortController();
    setPhase("loading");
    (async () => {
      try {
        const v = await api.version(ctl.signal);
        if (ctl.signal.aborted) return;
        setVersion(v);
        if (v.setup_required) {
          setPhase("setup");
          return;
        }
        try {
          const s = await api.session(ctl.signal);
          if (ctl.signal.aborted) return;
          setCsrfToken(s.csrf_token);
          setUser(s.user);
          setPhase("signed-in");
        } catch (err) {
          if (ctl.signal.aborted) return;
          if (err instanceof ApiError && err.isUnauthorized) {
            setPhase("anonymous");
            return;
          }
          throw err;
        }
      } catch (err) {
        if (ctl.signal.aborted) return;
        setError(err instanceof ApiError ? err : new ApiError(0, "client_error", "The dashboard could not start."));
        setPhase("error");
      }
    })();
    return () => ctl.abort();
  }, [attempt]);

  // Any signed-in request that answers 401 ends the session in the UI.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearScanCache();
      setCsrfToken("");
      setUser(null);
      setExpired(true);
      setPhase((p) => (p === "signed-in" ? "anonymous" : p));
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const signIn = useCallback((s: Session) => {
    clearScanCache();
    setCsrfToken(s.csrf_token);
    setUser(s.user);
    setExpired(false);
    setPhase("signed-in");
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // The session is cleared locally even when the server cannot be reached.
    }
    // Data of the previous account must not stay in memory for the next one.
    clearScanCache();
    setCsrfToken("");
    setUser(null);
    setExpired(false);
    setPhase("anonymous");
  }, []);

  const setupDone = useCallback(() => {
    setVersion((v) => (v ? { ...v, setup_required: false } : v));
    setPhase("anonymous");
  }, []);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  const value = useMemo<AuthValue>(
    () => ({
      phase,
      user,
      version,
      error,
      expired,
      isAdmin: user?.role === "administrator",
      signIn,
      signOut,
      setupDone,
      retry,
    }),
    [phase, user, version, error, expired, signIn, signOut, setupDone, retry],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used inside AuthProvider");
  return v;
}
