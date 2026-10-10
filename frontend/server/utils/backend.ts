import type { H3Event } from 'h3'
import { getRequestHeader, proxyRequest } from 'h3'

/**
 * The panel is never published, every request reaches it through this server. Whatever sits in front (nginx, a CDN)
 * has to set X-Real-IP to the address it saw: X-Forwarded-For is plain client input and is never read.
 */
export function clientIp(event: H3Event) {
  const real = getRequestHeader(event, 'x-real-ip')?.trim()
  return real || event.node.req.socket.remoteAddress || undefined
}

export function backendBase(event?: H3Event) {
  const { backendUrl } = useRuntimeConfig(event)
  return String(backendUrl).replace(/\/$/, '')
}

export function proxyToBackend(event: H3Event, path = event.path) {
  if (/(^|\/)\.\.?(\/|$)/.test(decodeURIComponent(path.split('?')[0] ?? ''))) {
    throw createError({ statusCode: 400, statusMessage: 'Bad Request' })
  }

  const ip = clientIp(event)
  // the panel rate limits and records sessions by the address in X-Forwarded-For, so it is always overwritten
  return proxyRequest(event, `${backendBase(event)}${path}`, {
    headers: { 'x-real-ip': ip ?? '', 'x-forwarded-for': ip ?? '' },
  })
}
