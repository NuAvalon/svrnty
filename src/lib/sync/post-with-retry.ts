// src/lib/sync/post-with-retry.ts
// Bounded retry + exponential backoff around ONE already-built POST (the joiner-response deposit; Peter
// #174621: delivery retry/backoff is mandatory). Retries ONLY the transport — the caller builds + signs
// the body ONCE, so every attempt carries byte-identical bytes. A redelivered deposit is safe at the
// giver: accept is idempotent (a joiner already in the book is a no-op), so a retry after a lost ack
// cannot double-admit or overwrite the first greeting.
//
// RETRYABLE: a thrown fetch (offline / DNS / abort-on-timeout), 408, 425, 429, and any 5xx.
// NOT RETRYABLE: every other status (a 4xx is the relay refusing THIS body — resending it cannot help).
// Honest result: ok only on a real 2xx; otherwise the LAST failure's classifier + the attempts used.

export interface RetryOptions {
  /** Total tries including the first. Default 5 (waits ≈0.5s, 1s, 2s, 4s between them). */
  attempts?: number;
  /** First backoff in ms; doubles each retry. Default 500. */
  baseDelayMs?: number;
  /** Backoff ceiling in ms. Default 8000. */
  maxDelayMs?: number;
  /** Per-attempt timeout in ms (a hung request counts as a network error). Default 10000. */
  timeoutMs?: number;
  /** Injectable for tests. Default setTimeout. */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable for tests: returns [0,1). Default Math.random (jitter ±20%). */
  random?: () => number;
}

export interface PostResult {
  ok: boolean;
  /** HTTP status on a response, or 'network-error' when the last attempt threw / timed out. */
  status: number | string;
  /** How many POSTs were actually made (1 = first try landed or was non-retryable). */
  attempts: number;
}

export function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || (status >= 500 && status <= 599);
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export async function postWithRetry(
  doFetch: typeof fetch,
  url: string,
  init: RequestInit,
  opts: RetryOptions = {},
): Promise<PostResult> {
  const attempts = Math.max(1, Math.floor(opts.attempts ?? 5));
  const base = opts.baseDelayMs ?? 500;
  const cap = opts.maxDelayMs ?? 8000;
  const timeoutMs = opts.timeoutMs ?? 10000;
  const sleep = opts.sleep ?? defaultSleep;
  const random = opts.random ?? Math.random;

  let last: { status: number | string } = { status: 'network-error' };
  for (let i = 1; i <= attempts; i++) {
    const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), timeoutMs) : null;
    try {
      const res = await doFetch(url, ctl ? { ...init, signal: ctl.signal } : init);
      if (res.ok) return { ok: true, status: res.status, attempts: i };
      last = { status: res.status };
      if (!isRetryableStatus(res.status)) return { ok: false, status: res.status, attempts: i };
    } catch {
      last = { status: 'network-error' };
    } finally {
      if (timer) clearTimeout(timer);
    }
    if (i < attempts) {
      const backoff = Math.min(cap, base * 2 ** (i - 1));
      await sleep(Math.round(backoff * (0.8 + 0.4 * random())));
    }
  }
  return { ok: false, status: last.status, attempts };
}
