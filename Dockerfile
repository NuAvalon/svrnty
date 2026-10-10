FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# NEXT_PUBLIC_* are inlined into the CLIENT bundle at build time (they are NOT read at
# runtime), so a self-hoster's domain must be baked in HERE for client-side share links,
# QR codes, and slug URLs to point at their instance. Defaults to svrnty.is, so the
# managed build is unchanged. docker compose passes these from your .env — see
# docker-compose.yml and .env.example.
ARG NEXT_PUBLIC_SVRNTY_DOMAIN=svrnty.is
ARG NEXT_PUBLIC_SVRNTY_BASE_URL=
ENV NEXT_PUBLIC_SVRNTY_DOMAIN=${NEXT_PUBLIC_SVRNTY_DOMAIN}
ENV NEXT_PUBLIC_SVRNTY_BASE_URL=${NEXT_PUBLIC_SVRNTY_BASE_URL}
# Build provenance (git commit / branch / build time). Unlike the NEXT_PUBLIC_* vars
# above, these are NOT inlined into the bundle — /api/version reads them from
# process.env at runtime (that route is force-dynamic). NuAvalon/svrnty is a PUBLIC
# repo, so SHA/branch are non-secret and safe to expose. The deploy pipeline passes
# these via --build-arg GIT_SHA / GIT_BRANCH / BUILD_TIME (default "unknown" if omitted).
ARG GIT_SHA=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown
ENV BUILD_GIT_SHA=${GIT_SHA}
ENV BUILD_GIT_BRANCH=${GIT_BRANCH}
ENV BUILD_TIME=${BUILD_TIME}
RUN npm run build
# Drop dev-only dependencies from the runtime node_modules — `next start` needs prod
# deps only. Smaller image, smaller attack surface.
RUN npm prune --omit=dev

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
# Build provenance for the runtime stage. ARGs are stage-scoped in Docker, so re-declare
# them here — the same --build-arg values the pipeline passes populate both stages. These
# ENVs are what /api/version actually reads from process.env at request time (next start
# runs in THIS stage). Placed after the COPYs so a changed stamp only busts this tiny
# layer, not the copy-layer cache.
ARG GIT_SHA=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown
ENV BUILD_GIT_SHA=${GIT_SHA}
ENV BUILD_GIT_BRANCH=${GIT_BRANCH}
ENV BUILD_TIME=${BUILD_TIME}
USER nextjs
EXPOSE 3000
CMD ["npx", "next", "start", "-p", "3000"]
