// Solar Ember tokens — CURSOR.md (Peter-approved). UI-only; no security logic.
// Colors are CSS variables so light/dark (and later custom UI prefs) swap without
// rewriting every component. Literals live in app/globals.css.

export type Appearance = 'dark' | 'light';

/** localStorage key for UI prefs. Shape is extensible (appearance today; accents later). */
export const UI_PREFS_KEY = 'svrnty.ui';

export type UiPrefs = {
  appearance: Appearance;
  // future: accent?, density?, motion?…
};

export const DEFAULT_UI_PREFS: UiPrefs = {
  appearance: 'dark',
};

export const solarEmber = {
  bg: 'var(--se-bg)',
  surface: 'var(--se-surface)',
  surfaceSolid: 'var(--se-surface-solid)',
  border: 'var(--se-border)',
  borderLit: 'var(--se-border-lit)',
  accent: 'var(--se-accent)',
  accent2: 'var(--se-accent2)',
  text: 'var(--se-text)',
  muted: 'var(--se-muted)',
  dim: 'var(--se-dim)',
  danger: 'var(--se-danger)',
  ok: 'var(--se-ok)',
  bgCss: 'var(--se-bg-css)',
  inputBg: 'var(--se-input-bg)',
  fontSans: "var(--font-sans), 'Space Grotesk', system-ui, sans-serif",
  fontMono: "var(--font-mono), 'JetBrains Mono', monospace",
  fontSerif: "var(--font-serif), 'Cormorant Garamond', serif",
} as const;

export const solarGlass: Record<string, string | number> = {
  background: 'var(--se-surface-solid)',
  backdropFilter: 'blur(20px)',
  WebkitBackdropFilter: 'blur(20px)',
  border: '1px solid var(--se-border)',
  borderRadius: 16,
  boxShadow: 'var(--se-glass-shadow)',
};

export function parseUiPrefs(raw: string | null): UiPrefs {
  if (!raw) return { ...DEFAULT_UI_PREFS };
  try {
    const parsed = JSON.parse(raw) as Partial<UiPrefs>;
    const appearance =
      parsed.appearance === 'light' || parsed.appearance === 'dark'
        ? parsed.appearance
        : DEFAULT_UI_PREFS.appearance;
    return { appearance };
  } catch {
    return { ...DEFAULT_UI_PREFS };
  }
}

export function applyAppearanceToDocument(appearance: Appearance) {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  root.setAttribute('data-appearance', appearance);
  root.classList.toggle('dark', appearance === 'dark');
}
