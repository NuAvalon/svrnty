'use client';

// UI prefs — appearance (light/dark) today; extend UiPrefs later for custom accents etc.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import {
  UI_PREFS_KEY,
  DEFAULT_UI_PREFS,
  applyAppearanceToDocument,
  parseUiPrefs,
  type Appearance,
  type UiPrefs,
} from '@/components/recovery/solar-ember';

type AppearanceContextValue = {
  appearance: Appearance;
  setAppearance: (next: Appearance) => void;
  toggleAppearance: () => void;
  prefs: UiPrefs;
};

const AppearanceContext = createContext<AppearanceContextValue | null>(null);

function readPrefs(): UiPrefs {
  if (typeof window === 'undefined') return { ...DEFAULT_UI_PREFS };
  return parseUiPrefs(localStorage.getItem(UI_PREFS_KEY));
}

export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<UiPrefs>(DEFAULT_UI_PREFS);

  useEffect(() => {
    const loaded = readPrefs();
    setPrefs(loaded);
    applyAppearanceToDocument(loaded.appearance);
  }, []);

  const persist = useCallback((next: UiPrefs) => {
    setPrefs(next);
    applyAppearanceToDocument(next.appearance);
    try {
      localStorage.setItem(UI_PREFS_KEY, JSON.stringify(next));
    } catch {
      /* private mode / quota — appearance still applies for this session */
    }
  }, []);

  const setAppearance = useCallback(
    (appearance: Appearance) => {
      setPrefs((prev) => {
        const next = { ...prev, appearance };
        applyAppearanceToDocument(appearance);
        try {
          localStorage.setItem(UI_PREFS_KEY, JSON.stringify(next));
        } catch {
          /* ignore */
        }
        return next;
      });
    },
    []
  );

  const toggleAppearance = useCallback(() => {
    setAppearance(prefs.appearance === 'dark' ? 'light' : 'dark');
  }, [prefs.appearance, setAppearance]);

  const value = useMemo(
    () => ({
      appearance: prefs.appearance,
      setAppearance,
      toggleAppearance,
      prefs,
    }),
    [prefs, setAppearance, toggleAppearance]
  );

  return (
    <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>
  );
}

export function useAppearance(): AppearanceContextValue {
  const ctx = useContext(AppearanceContext);
  if (!ctx) {
    throw new Error('useAppearance must be used within AppearanceProvider');
  }
  return ctx;
}
