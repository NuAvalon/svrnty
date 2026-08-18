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
USER nextjs
EXPOSE 3000
CMD ["npx", "next", "start", "-p", "3000"]
