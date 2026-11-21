# syntax=docker/dockerfile:1
FROM oven/bun:1 AS build
WORKDIR /src
ENV NUXT_TELEMETRY_DISABLED=1

COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

COPY . .
RUN --mount=type=cache,target=/src/node_modules/.cache \
    bun run build

FROM oven/bun:1-slim
WORKDIR /app

COPY --from=build /src/.output ./.output

ENV HOST=0.0.0.0
ENV PORT=3000
ENV NUXT_BACKEND_URL=http://panel:8080
EXPOSE 3000
USER bun
ENTRYPOINT ["bun", ".output/server/index.mjs"]
