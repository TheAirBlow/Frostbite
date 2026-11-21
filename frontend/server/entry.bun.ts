// @ts-expect-error virtual module that only exists in the nitro build
import '#nitro-internal-pollyfills'
import { useNitroApp } from 'nitropack/runtime'
import wsAdapter from '#crossws-bun'

/** Nitro's bun entry, plus the Bun server and request in the event context so the peer address is known. */
const nitroApp = useNitroApp()
// h3 types crossws through its .d.ts and the adapter through .d.mts, the same hooks either way
const ws = wsAdapter(nitroApp.h3App.websocket as Parameters<typeof wsAdapter>[0])

const server = Bun.serve({
  port: process.env.NITRO_PORT || process.env.PORT || 3000,
  hostname: process.env.NITRO_HOST || process.env.HOST,
  idleTimeout: Number.parseInt(process.env.NITRO_BUN_IDLE_TIMEOUT ?? '') || undefined,
  websocket: ws.websocket,
  async fetch(req, server) {
    if (req.headers.get('upgrade') === 'websocket') return ws.handleUpgrade(req, server)

    const url = new URL(req.url)
    return nitroApp.localFetch(url.pathname + url.search, {
      host: url.hostname,
      protocol: url.protocol,
      headers: req.headers,
      method: req.method,
      redirect: req.redirect,
      body: req.body ? await req.arrayBuffer() : undefined,
      context: { _platform: { bun: { server, request: req } } },
    })
  },
})

console.log(`Listening on ${server.url}...`)
