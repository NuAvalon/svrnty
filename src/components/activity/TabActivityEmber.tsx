'use client';

/**
 * Small ember on a tab. Binary: on or off. Never a number.
 *
 * The dot is DECORATIVE (aria-hidden): an aria-label on a role-less span is not reliably exposed. The tab announces the fact itself: its trigger
 * carries an aria-label ONLY while lit ("Galaxy, new activity" / "Chat, new messages", Hypatia #915), and no aria-label otherwise, so the name is
 * the plain visible text. A STATIC aria-label on the trigger is the bug this replaces: it overrides the content and the ember was never announced.
 * (A visually-hidden span inside the tab was tried first: Chromium inserts a space before an absolutely-positioned child, giving "Chat , new
 * messages".)
 */
export function TabActivityEmber({
  on,
  label,
  testId,
}: {
  on: boolean;
  /** Tooltip for sighted users, e.g. "new activity". The spoken name lives on the tab trigger (see page.tsx). */
  label: string;
  testId: string;
}) {
  if (!on) return null;
  return <span data-testid={testId} className="tab-ember" aria-hidden="true" title={label} />;
}
