'use client';

/** Small ember on a tab. Binary: on or off. Never a number. */
export function TabActivityEmber({
  on,
  label,
  testId,
}: {
  on: boolean;
  label: string;
  testId: string;
}) {
  if (!on) return null;
  return (
    <span
      data-testid={testId}
      className="tab-ember"
      aria-label={label}
      title={label}
    />
  );
}
