import './globals.css'

export const metadata = {
  title: 'Soverentity — Self-Sovereign Trust Network',
  description: 'Your keys, your data, your trust. Decentralized identity and contact management with post-quantum encryption.',
  manifest: '/manifest.json',
  themeColor: '#c8a84e',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'black-translucent',
    title: 'Soverentity',
  },
}

export const viewport = {
  themeColor: '#c8a84e',
  width: 'device-width',
  initialScale: 1,
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <head>
        <link rel="icon" href="/icon-192.svg" type="image/svg+xml" />
        <link rel="apple-touch-icon" href="/icon-192.svg" />
      </head>
      <body>
        {children}
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