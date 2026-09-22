// app/c/page.tsx — Landing route for shortcode relay links (svrnty.is/c/{code}#{key}).
// PARAM-FREE shell (Node Zero G-D coverage): middleware rewrites /c/<code> → /c (URL preserved),
// so the shortcode lives ONLY in window.location, never in a Next dynamic segment. A dynamic
// [code] segment would echo the code into the RSC flight-data inline script → /c/x ≠ /c/y in
// prod (KB#3220), breaking content-addressing + hash-CSP. This route already read its own URL
// client-side (the key fragment never reaches the server anyway), so dropping the segment is a
// no-op for behavior and the fix for byte-stability.
//
// Next.js plumbing only: it reads its OWN URL and hands off to the joiner ceremony. The parse
// goes through the SHARED parseInviteUrl boundary (INV-4) — the same one the in-page paste field
// (JoinByCode) and the QR camera use — so route/button/camera never diverge (one parser, gate-3
// as code). The fragment (key) never reaches the server: the whole exchange decrypts locally.
// All ceremony/import logic lives in JoinerCeremony.
"use client";

import { useEffect, useState } from 'react';
import { JoinerCeremony } from '@/components/JoinerCeremony';
import { parseInviteUrl, type ParsedInvite } from '@/lib/invite/parseInviteUrl';

export default function RelayCeremonyPage() {
  const [invite, setInvite] = useState<ParsedInvite | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    // ONE parser: the route validates its own full URL through the shared boundary.
    // The key lives only in the URL fragment — parseInviteUrl reads it, never logs it.
    setInvite(parseInviteUrl(window.location.href));
    setReady(true);
  }, []);

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
