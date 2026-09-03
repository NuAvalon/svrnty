// app/c/[code]/page.tsx
// Landing route for shortcode relay links (svrnty.is/c/{code}#{key}).
// Next.js plumbing only: it reads its OWN URL and hands off to the joiner ceremony. The
// parse goes through the SHARED parseInviteUrl boundary (INV-4) — the same one the in-page
// paste field (JoinByCode) and the QR camera use — so route/button/camera never diverge
// (one parser, gate-3 as code). The fragment (key) never reaches the server: the
// whole exchange decrypts locally. All ceremony/import logic lives in JoinerCeremony.
"use client";

import { useEffect, useState } from 'react';
import { JoinerCeremony } from '@/components/JoinerCeremony';
import { parseInviteUrl, type ParsedInvite } from '@/lib/invite/parseInviteUrl';

export default function RelayCeremonyPage({ params }: { params: Promise<{ code: string }> }) {
  const [invite, setInvite] = useState<ParsedInvite | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      // Resolve the route promise (Next async params) before touching window.
      await params;
      if (cancelled) return;
      // ONE parser: the route validates its own full URL through the shared boundary.
      // The key lives only in the URL fragment — parseInviteUrl reads it, never logs it.
      setInvite(parseInviteUrl(window.location.href));
      setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [params]);

  if (!ready) {
    return <Centered>Opening the link…</Centered>;
  }

  if (!invite) {
    return (
      <Centered>
        <span style={{ color: '#ef4444' }}>Missing decryption key.</span> The link may be
        incomplete.{' '}
        <a href="/" style={{ color: '#34d399', textDecoration: 'underline' }}>Go to SVRNTY</a>
      </Centered>
    );
  }

  return <JoinerCeremony code={invite.code} keyFragment={invite.keyFragment} />;
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
