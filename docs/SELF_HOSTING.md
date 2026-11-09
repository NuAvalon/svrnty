# Self-hosting svrnty

Run svrnty on your own domain, under your own control. Your instance is fully sovereign:
identity is **self-certifying** (a durable id derived from your own key material), so your
server needs no permission from — and no ongoing connection to — the managed `svrnty.is`.
That's the "tree in the seed": `svrnty.is` is a *default*, never a dependency.

This guide uses Docker Compose + Caddy (for automatic HTTPS). Total setup is a few minutes.

---

## What runs

`docker compose up` starts three services:

| Service | What it is | Data it keeps |
|---------|------------|---------------|
| `app` | the svrnty web app, including its relay (the encrypted mailbox peers drop messages into) | `relay_data` volume: the relay's SQLite mailbox of encrypted envelopes waiting for pickup |
| `registration` | the **satellite**: the crypto backend behind the app's `/api/satellite/*` routes (register, bind, contacts/allowed sync, PSI discovery, onion routing, trust sync) | `registration_data` volume: its SQLite database and its own mailbox key |
| `caddy` | HTTPS for your domain (automatic Let's Encrypt) | `caddy_data` / `caddy_config` volumes: certificates |

Only Caddy is published (ports 80/443). The app and the satellite are reachable only inside the
compose network. The one thing that stays on `svrnty.is` is the **global** username registry
(`/slug/{name}/claim`); on your instance that lookup degrades gracefully.

Dropping the `registration` service leaves a blind relay only: the `/api/satellite/*` routes
return 502, so identities can't register or bind and discovery doesn't work. Most self-hosters
want all three.

---

## Prerequisites

- A server with **Docker** and the **Docker Compose plugin**.
- A **domain** you control (e.g. `id.example.com`).
- **DNS**: an `A` record (and `AAAA` if you have IPv6) for that domain pointing at the server.
- **Ports 80 and 443** open to the internet — Caddy uses them to obtain a Let's Encrypt
  certificate automatically.

---

## Quick start

```bash
git clone https://github.com/NuAvalon/svrnty.git
cd svrnty
cp .env.example .env
# edit .env: set NEXT_PUBLIC_SVRNTY_DOMAIN to your domain, and
# SATELLITE_ADMIN_KEY to a random secret:  openssl rand -hex 32
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
| `SATELLITE_ADMIN_KEY` | **yes** | `SATELLITE_ADMIN_KEY` lets you run the satellite's housekeeping, which deletes messages that are past their retention period. It cannot read anyone's messages. The satellite won't start without it (20+ characters; `openssl rand -hex 32`), and `docker compose up` stops with an error until it's set. Server-side only: never a `NEXT_PUBLIC_` var, never logged. (The satellite's `/export` self-host kit generates its own key the same way.) |
| `SATELLITE_TRUSTED_PROXY_NAMES` | no | Who may pass the real client address to the satellite. Default `app` (the only hop in front of it). Leave it unless you change the topology. |
| `SATELLITE_URL` | no | The app's address for the satellite. Compose sets `http://registration:8101`. |
| `REGISTRATION_IMAGE` | no | Use a prebuilt satellite image instead of building `infra/svrnty`. |

### ⚠ Your domain is baked in at *build* time — rebuild if you change it

`NEXT_PUBLIC_*` values are compiled into the browser bundle when the image is **built**,
not read when the container **runs**. This is a Next.js rule, not a svrnty choice. The
compose file therefore passes your domain as a **build argument**, and `docker compose up`
includes `--build`.

The practical consequence: **if you change your domain, you must rebuild** —
`docker compose up -d --build`. Restarting alone will leave the old domain in the
client-side links. (Server-side values *are* read at runtime and take
effect on a plain restart.)

---

## The satellite service (`registration`)

The satellite is built from `infra/svrnty` (the open-source satellite source) and runs by
default; there is no profile to enable. Two rules:

- **Keep the service name `registration`.** One slug route resolves the satellite at the
  in-network host `registration:8101`, so renaming the service breaks it.
- **Set `SATELLITE_ADMIN_KEY`** (see the table above) before the first `up`.

Check it's healthy: `docker compose ps` shows `registration` as `healthy`, and
`docker compose logs registration` prints `[satellite] Mode: FULL`.

### Housekeeping: old messages are not deleted automatically

Nothing deletes old messages unless you run the satellite's cleanup. It removes undelivered
messages older than 30 days (the default) and delivered messages past the retention period. Run it from
inside the stack (the key never leaves the container), for example daily from cron:

```bash
docker compose exec -T registration python3 -c "import os,urllib.request as u; [u.urlopen(u.Request('http://localhost:8101'+p, method='POST', headers={'X-Admin-Key': os.environ['SATELLITE_ADMIN_KEY']})) for p in ('/msg/cleanup','/admin/cleanup')]"
```

If you don't schedule it, old messages stay on the server.

> Not yet: your app does not pin your satellite's key, so a client can't detect a swapped
> satellite. A signed satellite identity that clients pin is planned; until it ships, don't
> describe a self-hosted satellite as pinned or verifiable.

---

## Operating notes

- **The relay is durable and single-instance.** The relay's mailbox (encrypted envelopes
  waiting for pickup) is a SQLite file on the `relay_data` volume, so pending messages
  survive restarts and rebuilds. It's one file for one `app` container: do **not** run
  multiple `app` replicas behind a load balancer; they would each have their own mailbox.
- **Updating:** `git pull && docker compose up -d --build`.
- **Backups:** see [Backups](#backups) below.
- **Logs:** `docker compose logs -f app` (or `registration`, `caddy`).

---

## Security hardening

- **Run behind Caddy as shipped.** The image already runs as a non-root `nextjs` user on an
  internal port; only Caddy publishes 80/443. Don't expose the app's port 3000 publicly —
  the TLS + header discipline lives at the Caddy edge.
- **If you replace Caddy with your own proxy,** it must set the `X-Svrnty-Client-IP` header to
  the real client address on every request to the app, overwriting anything the client sent. The
  app's per-client rate limits read that header and nothing else. If your proxy doesn't set it,
  nothing visibly fails: every user shares one bucket, so the whole instance gets 10 deposits and
  300 owner requests a minute (`RELAY_RATE_LIMIT_MAX`, `RELAY_OWNER_RATE_LIMIT_MAX`). If your proxy
  passes through a value the client sent, clients can choose their own bucket. (Caddy as shipped
  sets this header from the address connected to it.) This setup hasn't been tested end to end.
- **Deposit limits.** A deposit body is capped at 64 KiB, a mailbox at 1000 messages and 16 MiB, and all deposits together at a byte budget per minute. By default the budget comes from your own disk: the room left before the disk guard, divided by the minutes in one retention period, between 64 KiB and 24 MiB. The derived number is what protects a small disk; the 24 MiB ceiling is only a setting. Set `RELAY_GLOBAL_DEPOSIT_BYTES_PER_WINDOW` or `RELAY_MAILBOX_BYTES_CAP` to change them. Under a sustained flood the budget runs out early in each minute, so honest deposits are refused for as long as the flood lasts. It ends when the flood ends, instead of lasting until stored messages expire. If you replace Caddy, cap `/api/relay/*` request bodies at your proxy too.
- **If you put a CDN or load balancer in front of Caddy,** the address connected to Caddy is the
  CDN's, not your user's. Users behind the same edge then share a bucket, and one sender gets a
  fresh budget on every edge. To fix it, list only your CDN's published address ranges under
  Caddy's `trusted_proxies`, set `client_ip_headers` to your CDN's own single-value client address
  header (on Cloudflare, `Cf-Connecting-IP`), and change `{remote_host}` to `{client_ip}` on the
  `X-Svrnty-Client-IP` line in `Caddyfile`. Don't use `X-Forwarded-For` for this if you can avoid
  it: Caddy reads it from the left, and a client can supply the left-most entry. If you must, also
  set `trusted_proxies_strict`. Never trust any of these headers without `trusted_proxies`, or
  anyone can forge them. This setup hasn't been tested end to end either.
- **Secrets stay server-side.** Any operator secret must never
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

- **What must survive:** `registration_data` (the satellite's database and its private key:
  not reconstructible) and `relay_data` (encrypted envelopes still waiting for pickup; losing
  it loses undelivered messages). `caddy_data` holds TLS certificates; losing it just
  re-issues them.
- **What you do NOT need to back up:** the app's code/config (rebuild from git + `.env`). Keep
  `.env` itself somewhere safe: it holds `SATELLITE_ADMIN_KEY`.
- **`registration_data` contains your satellite's private key.** Encrypt its backups and keep
  them as secret as your `.env` file: a copy lets its holder decrypt traffic sealed to your
  satellite and pose as it.
- Your users' identity keys are never on this server: they stay on each user's own device,
  encrypted under their password.

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

> **Not wired in the app yet.** This section describes the protocol. The code for it exists, but nothing in the running app calls it, so you can't move relays this way today, and people on different instances can't yet reach each other.

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
- **`docker compose up` stops with "set SATELLITE_ADMIN_KEY".** Add it to `.env`
  (`openssl rand -hex 32`) and run `up` again.
- **Contacts, registration or discovery fail (502 from `/api/satellite/*`).** The satellite
  isn't running: `docker compose ps registration` and `docker compose logs registration`.
  The most common cause is a missing or short `SATELLITE_ADMIN_KEY`.
