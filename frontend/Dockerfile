# syntax=docker/dockerfile:1
FROM node:22-slim AS build
WORKDIR /src
ENV NUXT_TELEMETRY_DISABLED=1

COPY --from=oven/bun:1 /usr/local/bin/bun /usr/local/bin/bun

COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

COPY . .
RUN --mount=type=cache,target=/src/node_modules/.cache \
    node node_modules/nuxt/bin/nuxt.mjs build

FROM node:22-slim
WORKDIR /app

COPY --from=build /src/.output ./.output

ENV HOST=0.0.0.0
ENV PORT=3000
ENV NUXT_BACKEND_URL=http://panel:8080
EXPOSE 3000
USER node
ENTRYPOINT ["node", ".output/server/index.mjs"]
