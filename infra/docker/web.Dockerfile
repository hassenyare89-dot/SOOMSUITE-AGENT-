# syntax=docker/dockerfile:1.7
FROM node:22-bookworm-slim AS build
WORKDIR /web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc,required=false \
    --mount=type=secret,id=extra_ca,target=/run/secrets/extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi \
 && npm ci --no-audit --no-fund
COPY apps/web ./
ARG ADMIN_GATEWAY_URL=http://api-gateway-admin:8000
ARG PUBLIC_GATEWAY_URL=http://api-gateway-public:8000
ARG NEXT_PUBLIC_DEV_LOGIN=false
ENV NEXT_TELEMETRY_DISABLED=1 ADMIN_GATEWAY_URL=${ADMIN_GATEWAY_URL} \
    PUBLIC_GATEWAY_URL=${PUBLIC_GATEWAY_URL} NEXT_PUBLIC_DEV_LOGIN=${NEXT_PUBLIC_DEV_LOGIN}
RUN npm run build

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
WORKDIR /app
COPY --from=build --chown=node:node /web/.next/standalone ./
COPY --from=build --chown=node:node /web/.next/static ./.next/static
COPY --from=build --chown=node:node /web/public ./public
USER node
EXPOSE 3000
CMD ["node", "server.js"]
