// app/c/[code]/page.tsx
// Landing route for shortcode relay links (svrnty.is/c/{code}#{key}).
// Next.js plumbing only: read the code from the path and the AES key from the URL
// fragment, then hand off to the joiner ceremony. The fragment (key) never reaches the
// server — the whole exchange decrypts locally. All the ceremony/import logic lives in
// JoinerCeremony (mirror of the initiator's Ceremony component — one impl, not two).
"use client";

import { useEffect, useState } from 'react';
import { JoinerCeremony } from '@/components/JoinerCeremony';

export default function RelayCeremonyPage({ params }: { params: Promise<{ code: string }> }) {
  const [code, setCode] = useState<string>('');
  const [keyFragment, setKeyFragment] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const [missingKey, setMissingKey] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const { code: resolved } = await params;
      if (cancelled) return;
      setCode(resolved);
      // The key lives only in the URL fragment — never sent to the server.
      const hash = window.location.hash;
      if (!hash || hash.length < 2) {
        setMissingKey(true);
        setReady(true);
        return;
      }
      setKeyFragment(hash.slice(1));
      setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [params]);

  if (!ready) {
    return <Centered>Opening the link…</Centered>;
  }

  if (missingKey || !keyFragment) {
    return (
      <Centered>
        <span style={{ color: '#ef4444' }}>Missing decryption key.</span> The link may be
        incomplete.{' '}
        <a href="/" style={{ color: '#34d399', textDecoration: 'underline' }}>Go to SVRNTY</a>
      </Centered>
    );
  }

  return <JoinerCeremony code={code} keyFragment={keyFragment} />;
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        background: '#0a0a0f',
        color: 'rgba(255,255,255,0.55)',
        fontFamily: "'Space Grotesk', sans-serif",
        fontSize: 14,
        textAlign: 'center',
      }}
    >
      <div style={{ maxWidth: 360 }}>{children}</div>
    </div>
  );
}
