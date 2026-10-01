// app/u/[name]/page.tsx
// There is no public directory. A single-segment path still lands here
// (middleware rewrites /:name → /u/:name) so the page can say so plainly.
'use client';

import { useParams } from 'next/navigation';
import Link from 'next/link';

export default function ProfilePage() {
  const params = useParams();
  const raw = params?.name;
  const name = typeof raw === 'string' ? raw : '';

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0a0a0f',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center',
      alignItems: 'center',
      padding: '20px',
      textAlign: 'center',
    }}>
      {name ? (
        <h1 style={{
          fontFamily: "'Cormorant Garamond', serif",
          fontSize: '28px',
          fontWeight: 300,
          color: '#e8e4d9',
          letterSpacing: '2px',
          marginBottom: '12px',
        }}>
          {name}
        </h1>
      ) : null}
      <p style={{
        fontFamily: "'Space Grotesk', sans-serif",
        fontSize: '14px',
        color: 'rgba(255,255,255,0.45)',
        marginBottom: '28px',
        maxWidth: '360px',
        lineHeight: 1.5,
      }}>
        There is no public page for this name.
      </p>
      <Link
        href="/"
        style={{
          border: '1px solid rgba(255,255,255,0.18)',
          borderRadius: '8px',
          padding: '12px 22px',
          color: '#e8e4d9',
          fontSize: '12px',
          fontWeight: 500,
          fontFamily: "'Space Grotesk', sans-serif",
          letterSpacing: '1px',
          textDecoration: 'none',
        }}
      >
        Back home
      </Link>
    </div>
  );
}
