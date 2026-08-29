// Solar Ember tokens — CURSOR.md (Peter-approved). UI-only; no security logic.

export const solarEmber = {
  bg: '#0f0a06',
  surface: 'rgba(30,20,10,.55)',
  surfaceSolid: 'rgba(28,19,10,.92)',
  border: 'rgba(255,190,120,.10)',
  borderLit: 'rgba(255,170,70,.38)',
  accent: '#f9a825',
  accent2: '#ff7a1a',
  text: '#fbead2',
  muted: '#c9a271',
  dim: '#8f7550',
  danger: '#ff8f7a',
  ok: '#c8e6a0',
  bgCss: 'radial-gradient(70% 70% at 50% 42%, rgba(249,168,37,.14), transparent 60%), #0f0a06',
  fontSans: "var(--font-sans), 'Space Grotesk', system-ui, sans-serif",
  fontMono: "var(--font-mono), 'JetBrains Mono', monospace",
  fontSerif: "var(--font-serif), 'Cormorant Garamond', serif",
} as const;

export const solarGlass: Record<string, string | number> = {
  background: 'rgba(30,20,10,.55)',
  backdropFilter: 'blur(20px)',
  WebkitBackdropFilter: 'blur(20px)',
  border: '1px solid rgba(255,190,120,.10)',
  borderRadius: 16,
  boxShadow: '0 0 40px rgba(249,168,37,.06)',
};

