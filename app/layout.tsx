import './globals.css'
import localFont from 'next/font/local'
import { AppearanceProvider } from '@/components/ui-prefs/AppearanceProvider'
import { UI_PREFS_KEY } from '@/components/recovery/solar-ember'

// Fonts are served locally — no build-time dependency on fonts.googleapis.com / fonts.gstatic.com.
// Each family's latin subset is a single Google *variable* woff2 (its wght axis spans all the
// weights below), committed under public/fonts/. One src entry per weight mirrors the prior
// Google-hosted output; the repeated per-family path is intentional (one variable file covers
// the whole weight range).
const jetbrainsMono = localFont({
  src: [
    { path: '../public/fonts/JetBrainsMono.woff2', weight: '300', style: 'normal' },
    { path: '../public/fonts/JetBrainsMono.woff2', weight: '400', style: 'normal' },
    { path: '../public/fonts/JetBrainsMono.woff2', weight: '500', style: 'normal' },
    { path: '../public/fonts/JetBrainsMono.woff2', weight: '600', style: 'normal' },
    { path: '../public/fonts/JetBrainsMono.woff2', weight: '700', style: 'normal' },
  ],
  variable: '--font-mono',
  display: 'swap',
})

const cormorantGaramond = localFont({
  src: [
    { path: '../public/fonts/CormorantGaramond.woff2', weight: '300', style: 'normal' },
    { path: '../public/fonts/CormorantGaramond.woff2', weight: '400', style: 'normal' },
    { path: '../public/fonts/CormorantGaramond.woff2', weight: '500', style: 'normal' },
  ],
  variable: '--font-serif',
  display: 'swap',
})

const spaceGrotesk = localFont({
  src: [
    { path: '../public/fonts/SpaceGrotesk.woff2', weight: '300', style: 'normal' },
    { path: '../public/fonts/SpaceGrotesk.woff2', weight: '400', style: 'normal' },
    { path: '../public/fonts/SpaceGrotesk.woff2', weight: '500', style: 'normal' },
    { path: '../public/fonts/SpaceGrotesk.woff2', weight: '600', style: 'normal' },
  ],
  variable: '--font-sans',
  display: 'swap',
})

export const metadata = {
  title: 'svrnty — Self-Sovereign Trust Network',
  description: 'Self-Sovereign Trust Network',
}

export const viewport = {
  themeColor: '#c8a84e',
  width: 'device-width',
  initialScale: 1,
}

/** Apply stored appearance before paint to avoid a dark→light flash. */
const appearanceBoot = `
(function(){
  try {
    var raw = localStorage.getItem(${JSON.stringify(UI_PREFS_KEY)});
    var appearance = 'dark';
    if (raw) {
      var p = JSON.parse(raw);
      if (p && (p.appearance === 'light' || p.appearance === 'dark')) appearance = p.appearance;
    }
    document.documentElement.setAttribute('data-appearance', appearance);
    if (appearance === 'dark') document.documentElement.classList.add('dark');
    else document.documentElement.classList.remove('dark');
  } catch (e) {
    document.documentElement.setAttribute('data-appearance', 'dark');
    document.documentElement.classList.add('dark');
  }
})();
`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html
      lang="en"
      className={`dark ${jetbrainsMono.variable} ${cormorantGaramond.variable} ${spaceGrotesk.variable}`}
      data-appearance="dark"
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: appearanceBoot }} />
        <link rel="manifest" href="/manifest.json" />
        <meta name="theme-color" content="#c8a84e" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
        <link rel="icon" href="/icon-192.svg" type="image/svg+xml" />
        <link rel="apple-touch-icon" href="/icon-192.svg" />
      </head>
      <body>
        <div className="stars" />
        <AppearanceProvider>{children}</AppearanceProvider>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              if ('serviceWorker' in navigator) {
                navigator.serviceWorker.register('/sw.js').catch(() => {});
              }
            `,
          }}
        />
      </body>
    </html>
  )
}
