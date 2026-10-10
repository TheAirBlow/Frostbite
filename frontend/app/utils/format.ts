const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

// set by the language switcher so dates follow the interface language
let dateLocale: string | undefined
export function setFormatLocale(tag: string) {
  dateLocale = tag
}

export function formatBytes(n: number, digits = 1): string {
  if (!n || n < 0) return '0 B'
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  const v = n / 1024 ** i
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(digits)} ${units[i]}`
}

export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(dateLocale, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(dateLocale, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const rtf = new Intl.RelativeTimeFormat(dateLocale, { numeric: 'auto' })
  const diff = (new Date(iso).getTime() - Date.now()) / 1000
  const abs = Math.abs(diff)
  if (abs < 60) return rtf.format(Math.round(diff), 'second')
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  if (abs < 86400 * 60) return rtf.format(Math.round(diff / 86400), 'day')
  return rtf.format(Math.round(diff / (86400 * 30)), 'month')
}

export function daysLeft(iso: string | null | undefined): number | null {
  if (!iso) return null
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000)
}

export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  if (d > 0) return `${d}d ${h}h`
  const m = Math.floor((seconds % 3600) / 60)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

// two letter country code to its flag emoji
export function flag(code: string | null | undefined): string {
  if (!code || code.length !== 2) return '🌐'
  return String.fromCodePoint(...code.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0)))
}

export function percent(used: number, limit: number): number {
  if (!limit) return 0
  return Math.min(100, Math.round((used / limit) * 100))
}

export const GB = 1024 ** 3

export interface StatusMeta {
  label: string
  badge: string
  icon: string
}

export const statusMeta: Record<string, StatusMeta> = {
  active: { label: 'Active', badge: 'badge-success', icon: 'fa6-solid:circle-check' },
  on_hold: { label: 'On hold', badge: 'badge-info', icon: 'fa6-solid:hourglass-half' },
  limited: { label: 'Limited', badge: 'badge-warning', icon: 'fa6-solid:gauge-high' },
  expired: { label: 'Expired', badge: 'badge-error', icon: 'fa6-solid:calendar-xmark' },
  disabled: { label: 'Disabled', badge: 'badge-neutral', icon: 'fa6-solid:ban' },
}

export const protocolLabels: Record<string, string> = {
  vless: 'VLESS',
  vmess: 'VMess',
  trojan: 'Trojan',
  shadowsocks: 'Shadowsocks',
  hysteria2: 'Hysteria2',
  mtproto: 'MTProto',
  turnable: 'Turnable',
  tuic: 'TUIC',
  anytls: 'AnyTLS',
  naive: 'Naive',
  shadowtls: 'ShadowTLS',
  socks: 'SOCKS',
  http: 'HTTP',
  mixed: 'Mixed',
  forward: 'Relay',
  wireguard: 'WireGuard',
}

export const coreLabels: Record<string, string> = { xray: 'Xray', singbox: 'sing-box', edge: 'Edge', mtproto: 'MTProto', turnable: 'Turnable' }

export const resetLabels: Record<string, string> = {
  none: 'Never',
  day: 'Every day',
  week: 'Every week',
  month: 'Every month',
  year: 'Every year',
}

export function randomName(): string {
  const a = ['frost', 'polar', 'glacier', 'aurora', 'arctic', 'snow', 'icy', 'tundra', 'boreal', 'north']
  const b = ['fox', 'owl', 'wolf', 'hare', 'lynx', 'bear', 'seal', 'crow', 'elk', 'orca']
  const pick = (l: string[]) => l[Math.floor(Math.random() * l.length)]
  return `${pick(a)}-${pick(b)}-${Math.floor(Math.random() * 900 + 100)}`
}

// hands a text file to the browser as a download
export function downloadText(name: string, text: string) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  a.download = name
  a.click()
  URL.revokeObjectURL(a.href)
}
