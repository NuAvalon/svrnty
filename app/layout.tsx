import './globals.css'
import { JetBrains_Mono, Cormorant_Garamond, Space_Grotesk } from 'next/font/google'
import { AppearanceProvider } from '@/components/ui-prefs/AppearanceProvider'
import { UI_PREFS_KEY } from '@/components/recovery/solar-ember'

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['300', '400', '500', '600', '700'],
  variable: '--font-mono',
  display: 'swap',
})

const cormorantGaramond = Cormorant_Garamond({
  subsets: ['latin'],
  weight: ['300', '400', '500'],
  style: ['normal', 'italic'],
  variable: '--font-serif',
  display: 'swap',
})

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  weight: ['300', '400', '500', '600'],
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
