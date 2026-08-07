# mona.expert — Secure AI Agent Wrapper
# Multi-stage build for minimal production image

# ── Stage 1: Dependencies ──
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json ./
RUN corepack enable && \
    pnpm install --prod --frozen-lockfile 2>/dev/null || \
    npm install --omit=dev --ignore-scripts

# ── Stage 2: Runtime ──
FROM node:22-alpine
RUN addgroup -S mona && adduser -S mona -G mona

WORKDIR /app

# Copy only what's needed
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src/ ./src/
COPY server.js ./
COPY bin/ ./bin/
COPY public/ ./public/
COPY scripts/ ./scripts/
COPY docs/ ./docs/

# Create data directory with correct permissions
RUN mkdir -p .mona-dashboard && chown -R mona:mona /app

USER mona
EXPOSE 4188

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('node:http').get('http://127.0.0.1:4188/api/health', r => { process.exit(r.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

ENV MONA_EXPERT_PORT=4188
ENV NODE_ENV=production

CMD ["node", "--env-file", ".env", "server.js"]
