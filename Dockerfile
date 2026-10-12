# FINPAY SOC — one image for the web app, the worker and database migrations.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
COPY . .
RUN npm run build && npm prune --omit=dev --no-audit --no-fund

FROM node:22-alpine AS runtime
ENV NODE_ENV=production PORT=3000 HOST=0.0.0.0
WORKDIR /app
RUN apk add --no-cache tini wget && addgroup -S soc && adduser -S -G soc soc
COPY --from=build --chown=soc:soc /app/package.json /app/tsconfig.json ./
COPY --from=build --chown=soc:soc /app/node_modules ./node_modules
COPY --from=build --chown=soc:soc /app/.output ./.output
COPY --from=build --chown=soc:soc /app/src ./src
COPY --from=build --chown=soc:soc /app/scripts ./scripts
COPY --from=build --chown=soc:soc /app/db ./db
USER soc
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", ".output/server/index.mjs"]
