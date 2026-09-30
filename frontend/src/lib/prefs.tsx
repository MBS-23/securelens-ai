import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

/**
 * Per-viewer display preferences: colour theme, Learning vs Professional mode
 * and motion. Stored in localStorage as a convenience only — every read and
 * write is guarded, and the app works the same when storage is unavailable.
 */

export type Theme = "dark" | "light";
export type Mode = "learning" | "professional";
export type Motion = "full" | "reduced";

function systemPrefersReducedMotion(): boolean {
  try {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

function load<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const value = window.localStorage.getItem(key);
    return value && (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
  } catch {
    return fallback;
  }
}

function save(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* storage unavailable: keep the in-memory value */
  }
}

interface Prefs {
  theme: Theme;
  mode: Mode;
  setTheme: (theme: Theme) => void;
  setMode: (mode: Mode) => void;
  orgId: string | null;
  setOrgId: (id: string) => void;
  /** The viewer's choice; "reduced" disables page transitions and the animated mark. */
  motion: Motion;
  setMotion: (motion: Motion) => void;
  /** True when either the viewer or the operating system asks for reduced motion. */
  reduceMotion: boolean;
}

const PrefsContext = createContext<Prefs | null>(null);

export function PrefsProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => load("sl.theme", ["dark", "light"] as const, "dark"));
  const [mode, setModeState] = useState<Mode>(() =>
    load("sl.mode", ["learning", "professional"] as const, "professional"),
  );
  const [orgId, setOrgIdState] = useState<string | null>(() => {
    try {
      return window.localStorage.getItem("sl.org");
    } catch {
      return null;
    }
  });

  // The operating system's reduced-motion setting always wins; this choice can only reduce motion further.
  const [motion, setMotionState] = useState<Motion>(() => load("sl.motion", ["full", "reduced"] as const, "full"));
  const [systemReduced, setSystemReduced] = useState(systemPrefersReducedMotion);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    let query: MediaQueryList;
    try {
      query = window.matchMedia("(prefers-reduced-motion: reduce)");
    } catch {
      return;
    }
    const onChange = () => setSystemReduced(query.matches);
    query.addEventListener?.("change", onChange);
    return () => query.removeEventListener?.("change", onChange);
  }, []);

  const setTheme = useCallback((value: Theme) => {
    setThemeState(value);
    save("sl.theme", value);
  }, []);
  const setMode = useCallback((value: Mode) => {
    setModeState(value);
    save("sl.mode", value);
  }, []);
  const setOrgId = useCallback((value: string) => {
    setOrgIdState(value);
    save("sl.org", value);
  }, []);
  const setMotion = useCallback((value: Motion) => {
    setMotionState(value);
    save("sl.motion", value);
  }, []);

  const reduceMotion = motion === "reduced" || systemReduced;
  const value = useMemo(
    () => ({ theme, mode, setTheme, setMode, orgId, setOrgId, motion, setMotion, reduceMotion }),
    [theme, mode, setTheme, setMode, orgId, setOrgId, motion, setMotion, reduceMotion],
  );
  return <PrefsContext.Provider value={value}>{children}</PrefsContext.Provider>;
}

export function usePrefs(): Prefs {
  const ctx = useContext(PrefsContext);
  if (!ctx) throw new Error("usePrefs must be used inside PrefsProvider");
  return ctx;
}
