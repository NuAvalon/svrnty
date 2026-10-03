# Self-hosting svrnty

Run svrnty on your own domain, under your own control. Your instance is fully sovereign:
identity is **self-certifying** (a durable id derived from your own key material), so your
server needs no permission from — and no ongoing connection to — the managed `svrnty.is`.
That's the "tree in the seed": `svrnty.is` is a *default*, never a dependency.

This guide uses Docker Compose + Caddy (for automatic HTTPS). Total setup is a few minutes.

---

## Two ways to run it

| Tier | What runs | What you get | What you give up |
|------|-----------|--------------|------------------|
| **Minimal** (default) | the app + Caddy | Full identity, encrypted contact exchange (the relay dead-drop), the vault, import/export — everything client-side and self-contained | Vanity slugs (`id.example.com/alice`). Slug routes return "unavailable"; nothing else is affected. |
| **Full nursery** | the above **+** the registration backend | Also: vanity slugs on your own domain | You run one more service + its datastore |

Most people want **Minimal**. Add the nursery later if you want human-readable names.

---

## Prerequisites

- A server with **Docker** and the **Docker Compose plugin**.
- A **domain** you control (e.g. `id.example.com`).
- **DNS**: an `A` record (and `AAAA` if you have IPv6) for that domain pointing at the server.
- **Ports 80 and 443** open to the internet — Caddy uses them to obtain a Let's Encrypt
  certificate automatically.
- (Optional, for email verification) a [Resend](https://resend.com) API key and a sender
  address verified for your domain.

---

## Quick start (minimal)

```bash
git clone https://github.com/NuAvalon/svrnty.git
cd svrnty
cp .env.example .env
# edit .env — at minimum set NEXT_PUBLIC_SVRNTY_DOMAIN to your domain
docker compose up -d --build
```

Caddy will obtain a certificate on first request. Visit `https://your-domain` and create
your first identity.

---

## Configuration (`.env`)

| Variable | Required | Notes |
|----------|----------|-------|
| `NEXT_PUBLIC_SVRNTY_DOMAIN` | **yes** | Your bare domain, no scheme (e.g. `id.example.com`). Drives every share link, slug URL, and display string. |
| `NEXT_PUBLIC_SVRNTY_BASE_URL` | no | Override the full scheme+host. Defaults to `https://<your domain>`. Set this only for `http`/localhost during local testing. |
| `EMAIL_FROM` | for email verify | The "from" address for verification emails — must be a sender your provider has verified for your domain. |
| `RESEND_API_KEY` | for email verify | Server-side secret. **Never** prefix it with `NEXT_PUBLIC_` — that would ship it to the browser. |
| `SATELLITE_URL` | nursery only | Address of the registration backend. Compose sets this for you. |
| `REGISTRATION_IMAGE` | nursery only | Image for the registration backend. |

### ⚠ Your domain is baked in at *build* time — rebuild if you change it

`NEXT_PUBLIC_*` values are compiled into the browser bundle when the image is **built**,
not read when the container **runs**. This is a Next.js rule, not a svrnty choice. The
compose file therefore passes your domain as a **build argument**, and `docker compose up`
includes `--build`.

The practical consequence: **if you change your domain, you must rebuild** —
`docker compose up -d --build`. Restarting alone will leave the old domain in the
client-side links. (Server-side values like `RESEND_API_KEY` *are* read at runtime and take
effect on a plain restart.)

---

## Full nursery (vanity slugs)

Vanity slugs (`id.example.com/alice`) require the registration backend — the anti-squat
registry that maps a claimed name to an identity. It lives in `infra/svrnty`.

1. Build the registration image from `infra/svrnty` and set `REGISTRATION_IMAGE` in `.env`
   (packaging of a prebuilt image is tracked separately).
2. Bring the stack up with the nursery profile:

   ```bash
   docker compose --profile nursery up -d --build
   ```

**Keep the service name `registration`.** The slug-resolution route resolves the backend at
the in-network host `registration:8101`, so renaming the service breaks slug lookups even if
registration itself succeeds. The compose file is already set up correctly — just don't
rename it.

Without the nursery, slug routes return an "unavailable" response and the rest of the app is
unaffected — identities still work end-to-end via self-certifying ids and the relay.

---

## Operating notes

- **The relay is in-memory and single-instance.** The encrypted dead-drop used for contact
  exchange lives in the app process (single-use blobs, 15-minute TTL). This is ideal for a
  single-container instance. Do **not** run multiple `app` replicas behind a load balancer
  without first moving the relay to a shared store (e.g. Redis) — replicas would not see each
  other's drops. Restarting the app clears any in-flight (unclaimed) drops; since drops are
  single-use and short-lived, this is normally harmless.
- **Updating:** `git pull && docker compose up -d --build`.
- **Backups:** the `caddy_data` volume holds your TLS certificates; the `registration_data`
  volume (nursery only) holds your slug registry. Back these up.
- **Logs:** `docker compose logs -f app` (or `caddy`).

---

## Security hardening

- **Run behind Caddy as shipped.** The image already runs as a non-root `nextjs` user on an
  internal port; only Caddy publishes 80/443. Don't expose the app's port 3000 publicly —
  the TLS + header discipline lives at the Caddy edge.
- **Secrets stay server-side.** `RESEND_API_KEY` and any future operator secrets must never
  be named `NEXT_PUBLIC_*` — that prefix ships the value into the browser bundle. Keep real
  secrets out of the repo (`.env` is gitignored; `.env.example` holds placeholders only).
- **The relay learns nothing by design — keep it that way.** Don't add logging of drop
  contents, depositors, or mailbox ids beyond what the code emits. The blind-relay property
  (the server can't read drops or map who-talks-to-whom) is a product invariant, and an
  operator who weakens it weakens every user's privacy on that instance.
- **Rebuild on updates** (`git pull && docker compose up -d --build`) so `NEXT_PUBLIC_*`
  args and dependencies refresh together; verify `https://your-domain/api/version` reports
  the commit you expect.

## Backups

- **What must survive:** `caddy_data` (TLS certs — losing it just re-issues), and on the
  nursery profile `registration_data` (the slug registry — losing it loses every claimed
  slug's binding). Back up both volumes; `registration_data` is the only one that isn't
  reconstructible.
- **What you do NOT need to back up:** the app's code/config (rebuild from git + `.env`),
  and the in-memory relay (drops are single-use, 15-minute TTL — transient by design).
- A self-hoster's *identity* is never on this server — it lives in the user's `.svrnty`
  vault under their password. Server backup is about *service continuity*, not key custody.

## Build best practices

- **Pinned, reproducible:** `npm ci` everywhere (the Dockerfile does; CI does). Never
  `npm install` inside the image.
- **Build args are provenance, not config:** `GIT_SHA`/`GIT_BRANCH`/`BUILD_TIME` stamp
  `/api/version`; `NEXT_PUBLIC_*` bake the domain into the client. Rebuild when either
  changes — see the warning box above.
- **Image stays lean by design:** the runner stage carries prod `node_modules` only
  (`npm prune --omit=dev`); keep dev tooling out of the runtime stage.

---

## Migrating a mailbox to another relay

Your mailbox (where peers deposit envelopes for you) is **advertised, not glued**: peers
find it via a signed *mailbox pointer* you publish — changing relays means publishing a
newer pointer, not moving identity. Your durable id and DID are untouched by a move.

Conceptually, for each identity you host:

1. **Create the new mailbox** on the destination relay (`POST /mailbox/register` there —
   same owner-proof flow as the first registration).
2. **Publish the rotation** — a signed pointer with `pointerEpoch = previous + 1`, sealed
   to each peer's *current* mailbox keys (`publishMailboxPointer` in
   `src/lib/trust/mailbox-pointer-transport.ts`). Peers resolve the highest-epoch valid
   pointer, so the newest wins monotonically; a stale pointer can't roll you back.
3. **Keep the overlap window.** Your old mailbox's decapsulation key must stay valid until
   peers confirm receipt — a peer who sealed a deposit to the old mailbox before seeing the
   pointer still needs you able to open it. Don't retire the old mailbox the moment the new
   one exists.
4. **Verify, then retire.** Once pointer propagation is confirmed, drain the old mailbox
   and let it lapse. Nothing on the old relay can act as you — it only ever held envelopes
   it couldn't read.

> Harness status: the pointer rotation machinery is built and tested; an end-to-end
> scripted migration is tracked in `docs/FEDERATION_QA.md` (scenario S4). Until the
> fed-qa harness proves it green, treat this runbook as the protocol shape, not a
> verified click-path — and say so wherever you document it.

---

## Troubleshooting

- **No certificate / TLS errors on first load.** Confirm DNS points at this server and that
  ports 80 + 443 are reachable from the internet. Watch `docker compose logs -f caddy`.
- **Share links show `svrnty.is` instead of your domain.** The image was built without your
  domain. Rebuild: `docker compose up -d --build`, and confirm `NEXT_PUBLIC_SVRNTY_DOMAIN` is
  set in `.env`.
- **Verification emails don't send.** Check `RESEND_API_KEY` and that `EMAIL_FROM` is a
  sender verified for your domain with your provider.
- **Slug claims fail.** Vanity slugs need the nursery profile
  (`docker compose --profile nursery up -d --build`). Without it, this is expected.
