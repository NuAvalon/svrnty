// Shown on the home page while svrnty isn't live. Plain text and one mailto link: no state, no script of its own.
const CONTACT = 'nuavalon@proton.me';

export function NotLiveBanner() {
  return (
    <div
      role="note"
      data-testid="not-live-banner"
      style={{
        background: '#7c2d12',
        color: '#fff7ed',
        padding: '10px 16px',
        textAlign: 'center',
        fontSize: 14,
        lineHeight: 1.45,
      }}
    >
      svrnty isn&apos;t live yet. It&apos;s in development, so please don&apos;t rely on it. If you&apos;re using it, please email{' '}
      <a href={`mailto:${CONTACT}`} style={{ color: 'inherit', textDecoration: 'underline' }}>
        {CONTACT}
      </a>{' '}
      so we know.
    </div>
  );
}
