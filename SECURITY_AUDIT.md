# svrnty Security Audit — May 6, 2026

Auditor: Flint (red team, autobots)
Scope: Full codebase review — crypto, identity, API routes, frontend, middleware
Server: localhost:3333 (Next.js dev)

## Architecture Summary

Identity is 100% client-side (IndexedDB). Server only handles:
- Relay (encrypted dead drop, single-use shortcodes)
- Satellite proxy (registration + slug claim)
- Auth/slug lookup (proxy to registration:8101)
- Middleware (slug rewrite /peter -> /u/peter)

All former server-side identity/contacts/signals/keys routes return HTTP 410.

## Findings

### F1 — MEDIUM: Private keys unencrypted in IndexedDB — FIXED

**File:** `src/lib/identity/client-store.ts`
**Status:** Fixed (Fork 35-36)

Added session key encryption layer:
- PBKDF2 (600K iterations SHA-256) derives AES-256-GCM key from user passphrase
- Non-extractable CryptoKey held in memory, lost on tab close
- `storeKey()` encrypts transparently if session key exists
- `loadKey()` decrypts or returns legacy records (auto-migrates on read)
- Frontend now shows "Unlock Passphrase" field during identity creation
- Passphrase is recommended, not required (backward compat)

**Files changed:** `client-store.ts`, `browser-identity.ts`, `SoverentityFrontend.tsx`

---

### F2 — MEDIUM: Satellite proxy forwards raw body without validation — FIXED

**File:** `app/api/satellite/register/route.ts`, `app/api/satellite/slug/[name]/claim/route.ts`
**Status:** Fixed (Fork 36)

- Register: field allowlist (fingerprint, public_key, name, email, slug), 4KB max per field, requires fingerprint + public_key
- Slug claim: regex validation (`/^[a-z0-9][a-z0-9_-]{2,39}$/`), `encodeURIComponent()` on path, field allowlist
- Both: reject non-object bodies, reject arrays

**QA:** Tested path traversal (`../evil`) — rejected. Missing fields — rejected. Valid requests — proxied correctly.

---

### F3 — LOW: Passphrase minimum inconsistency — FIXED

**File:** `src/components/SoverentityFrontend.tsx`
**Status:** Fixed (Fork 36)

Changed browser minimum from 4 to 12 characters. Both identity creation unlock passphrase and "Set Passphrase" dialog now enforce 12-char minimum.

---

### F4 — LOW: Modulo bias in relay code generation — FIXED

**File:** `app/api/relay/route.ts`
**Status:** Fixed (Fork 36)

Replaced `bytes[i] % ALPHABET.length` with rejection sampling. Values >= `256 - (256 % 55)` are discarded, eliminating bias.

**QA:** Relay create/read/single-use flow verified working after fix.

---

### F5 — LOW: PQ secret key base64 conversion may exceed stack limit — FIXED

**File:** `src/lib/identity/browser-identity.ts`
**Status:** Fixed (Fork 36)

Replaced `btoa(String.fromCharCode(...bytes))` spread with loop-based `uint8ToBase64()` helper that iterates instead of spreading ~4KB arrays onto the call stack.

---

### F6 — INFO: Unsigned slug claims

**File:** `src/components/SoverentityFrontend.tsx`

Slug claim sends fingerprint without cryptographic proof of ownership. Anyone knowing a fingerprint could claim a slug for that identity.

**Fix:** Sign the claim request with the identity's private key. Verify server-side.

---

### F7 — INFO: Google Fonts import leaks IP — FIXED

**Files:** `app/layout.tsx`, `app/globals.css`, `app/page.tsx`, `app/u/[name]/page.tsx`, `SoverentityFrontend.tsx`
**Status:** Fixed (Fork 37)

Replaced all external `@import`/`<link>` Google Fonts references with `next/font/google` in layout.tsx. Fonts are now downloaded at build time and self-hosted — zero runtime requests to Google. CSS variables `--font-mono`, `--font-serif`, `--font-sans` available globally.

---

### F8 — INFO: In-memory relay store

**File:** `app/api/relay/route.ts`

`globalThis.__relayStore` is in-memory. Data lost on restart. Acceptable for MVP, needs Redis/persistent store for production.

---

### F9 — INFO: Parallel crypto implementations

**Files:** `src/lib/identity/core.ts` (Node.js crypto) vs `src/lib/identity/browser-identity.ts` (WebCrypto)

Two implementations of the same operations. Bug fixes must be applied to both.

---

### F10 — INFO: Hex seed phrase instead of BIP39 words

**File:** `src/lib/crypto/recovery.ts:201-208`

Seed phrase is 8 groups of 8 hex chars. Less memorable than BIP39 word lists. UX consideration, not a security bug.

---

### F11 — INFO: Rate limit spoofable without reverse proxy

**File:** `app/api/relay/route.ts:51-57`

Rate limiting keys on `x-forwarded-for`. Spoofable if not behind nginx. Expected to be behind reverse proxy in production.

---

### F12 — LOW: clearAll() has no confirmation gate — FIXED

**File:** `src/lib/identity/client-store.ts`
**Status:** Fixed (Fork 37)

Added required confirmation string parameter: `clearAll('I understand this deletes all keys')`. TypeScript enforces the literal string type — callers cannot pass arbitrary strings.

## Summary

| ID | Severity | Status | Description |
|----|----------|--------|-------------|
| F1 | MEDIUM | FIXED | IndexedDB key encryption (PBKDF2 + AES-256-GCM) |
| F2 | MEDIUM | FIXED | Satellite proxy input validation + field allowlist |
| F3 | LOW | FIXED | Passphrase minimum 4→12 chars |
| F4 | LOW | FIXED | Relay code modulo bias → rejection sampling |
| F5 | LOW | FIXED | PQ key base64 stack overflow risk |
| F6 | INFO | OPEN | Unsigned slug claims |
| F7 | INFO | FIXED | Google Fonts → next/font self-hosting |
| F8 | INFO | OPEN | In-memory relay store |
| F9 | INFO | OPEN | Parallel crypto implementations |
| F10 | INFO | OPEN | Hex seed phrase UX |
| F11 | INFO | OPEN | Rate limit spoofable without proxy |
| F12 | LOW | FIXED | clearAll() confirmation string gate |
| F13 | CRITICAL | FIXED | Next.js 15.1.7 → 15.5.16 (RCE, auth bypass, SSRF) |
| F14 | HIGH | FIXED | Nodemailer 6.x → 8.0.7 (SMTP injection, CRLF) |
| F15 | MEDIUM | MITIGATED | PostCSS XSS (bundled in Next.js — upstream) |

### npm audit status (May 7)
- **Before:** 6 vulnerabilities (1 critical, 2 high, 3 moderate)
- **After:** 2 moderate (postcss bundled in next — upstream fix pending)
- All critical/high resolved. E2E 15/15 pass after upgrade.
