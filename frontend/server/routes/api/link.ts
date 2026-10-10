import WebSocket from 'ws'

/**
 * Daemons keep a websocket open to the panel at /api/link. It is relayed here so the panel itself stays unpublished.
 * The upstream is opened while the upgrade is still pending, so a bad token is refused with a real 401.
 */
const peers = new Map<string, WebSocket>()

export default defineWebSocketHandler({
  async upgrade(req) {
    const base = backendBase().replace(/^http/, 'ws')
    const ip = req.headers.get('x-real-ip')?.trim() || undefined
    const upstream = new WebSocket(`${base}/api/link`, {
      headers: {
        authorization: req.headers.get('authorization') ?? '',
        'x-real-ip': ip ?? '',
        'x-forwarded-for': ip ?? '',
        'user-agent': req.headers.get('user-agent') ?? '',
      },
      maxPayload: 16 << 20,
    })

    await new Promise<void>((resolve, reject) => {
      upstream.once('open', () => resolve())
      upstream.once('unexpected-response', (_r, res) => {
        upstream.terminate()
        reject(new Response(res.statusMessage ?? 'rejected', { status: res.statusCode ?? 502 }))
      })
      upstream.once('error', () => reject(new Response('panel unreachable', { status: 502 })))
    })
    ;(req as { context: Record<string, unknown> }).context.upstream = upstream
  },

  open(peer) {
    const upstream = peer.context.upstream as WebSocket | undefined
    if (!upstream) {
      peer.close(1011, 'no upstream')
      return
    }
    upstream.on('message', (data, binary) => {
      if (binary) peer.send(data as Buffer)
      else peer.send(data.toString())
    })
    upstream.on('close', (code, reason) => peer.close(sendable(code), reason.toString()))
    upstream.on('error', () => peer.close(1011, 'upstream error'))
    peers.set(peer.id, upstream)
  },

  message(peer, message) {
    const upstream = peers.get(peer.id)
    const data = message.rawData as string | Buffer
    if (upstream?.readyState === WebSocket.OPEN) upstream.send(data)
  },

  close(peer) {
    peers.get(peer.id)?.close()
    peers.delete(peer.id)
  },

  error(peer) {
    peers.get(peer.id)?.terminate()
    peers.delete(peer.id)
  },
})

/** 1005, 1006 and 1015 describe a state and can never be sent in a close frame. */
function sendable(code: number) {
  return code === 1005 || code === 1006 || code === 1015 ? 1000 : code
}
