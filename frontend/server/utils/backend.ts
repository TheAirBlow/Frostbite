import type { H3Event } from 'h3'
import { getRequestHeader, proxyRequest } from 'h3'

/**
 * The panel is never published, every request reaches it through this server. Whatever sits in front (nginx, a CDN)
 * has to set the header named by FROSTBITE_IP_HEADER (X-Real-IP by default) to the address it saw.
 */
export const ipHeader = (process.env.FROSTBITE_IP_HEADER?.trim() || 'x-real-ip').toLowerCase()

/** The client address from the configured header. Of a list, the last entry is the one the nearest proxy added. */
export function forwardedIp(value: string | null | undefined) {
  return value?.split(',').pop()?.trim() || undefined
}

export function clientIp(event: H3Event) {
  return forwardedIp(getRequestHeader(event, ipHeader)) || event.node.req.socket.remoteAddress || undefined
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
