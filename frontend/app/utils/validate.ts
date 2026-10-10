// Small checks used by form rules. Each returns an error message, or undefined when the value is fine.
// The messages are plain English: FormField runs them through the translator when it shows them.

export type Check = string | undefined

const HOST_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i

export function checkRequired(v: unknown, message = 'This is required'): Check {
  if (v === null || v === undefined) return message
  if (typeof v === 'string' && v.trim() === '') return message
  if (Array.isArray(v) && v.length === 0) return message
  return undefined
}

export function checkIp(v: string): Check {
  const s = v.trim()
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split('.').every(n => Number(n) <= 255)) return undefined
  if (s.includes(':') && /^[0-9a-f:.]+$/i.test(s) && s.split(':').length >= 3 && s.split(':').length <= 8) return undefined
  return 'That is not a valid IP address'
}

export function isIp(v: string): boolean {
  return checkIp(v) === undefined
}

export function checkDomain(v: string): Check {
  const s = v.trim().replace(/\.$/, '')
  if (!s || s.length > 253) return 'That is not a valid domain name'
  const labels = s.split('.')
  if (labels.length < 2 || !labels.every(l => HOST_LABEL.test(l))) return 'That is not a valid domain name'
  return undefined
}

// a domain or an IP address, without a scheme or a path
export function checkHost(v: string): Check {
  const s = v.trim()
  if (/[\s/\\]/.test(s) || s.includes('://')) return 'Use a bare domain or IP address, without a scheme, path or spaces'
  if (isIp(s) || /^\[[0-9a-f:.]+\]$/i.test(s)) return undefined
  if (/^[\d.]+$/.test(s)) return 'That is not a valid IP address'
  return checkDomain(s)
}

export function checkPort(v: unknown): Check {
  const n = typeof v === 'number' ? v : Number(v)
  if (v === '' || v === null || v === undefined || Number.isNaN(n)) return 'Enter a port number'
  if (!Number.isInteger(n) || n < 1 || n > 65535) return 'Use a port from 1 to 65535'
  return undefined
}

// 10.0.0.1:443, example.com:443 or [::1]:443
export function checkHostPort(v: string, opts: { ipOnly?: boolean } = {}): Check {
  const s = v.trim()
  const m = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(s) ?? /^(.+):(\d+)$/.exec(s)
  if (!m) return 'It must look like host:port, for example 10.0.0.1:443'
  const host = m[1]!.replace(/^\[|\]$/g, '')
  const port = checkPort(m[2])
  if (port) return port
  if (opts.ipOnly) return isIp(host) ? undefined : 'The host must be an IP address'
  return isIp(host) || checkDomain(host) === undefined ? undefined : 'The host is not a valid domain or IP address'
}

export function checkCidr(v: string): Check {
  const [ip, bits, ...rest] = v.trim().split('/')
  if (rest.length || !ip || checkIp(ip)) return 'Use an IP range like 10.0.0.0/8'
  if (bits === undefined) return undefined
  const n = Number(bits)
  const max = ip.includes(':') ? 128 : 32
  return Number.isInteger(n) && n >= 0 && n <= max && /^\d+$/.test(bits) ? undefined : 'Use an IP range like 10.0.0.0/8'
}

export function checkUrl(v: string, schemes: string[] = ['http:', 'https:']): Check {
  try {
    const u = new URL(v.trim())
    if (!schemes.includes(u.protocol)) return `The address must start with ${schemes.map(s => `${s}//`).join(' or ')}`
    if (!u.host) return 'That is not a valid address'
    return undefined
  }
  catch {
    return 'That is not a valid address'
  }
}

export function checkEmail(v: string): Check {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim()) ? undefined : 'That does not look like an email address'
}

export function checkInt(v: unknown, min = -Infinity, max = Infinity, what = 'a number'): Check {
  const n = typeof v === 'number' ? v : Number(v)
  if (v === '' || v === null || v === undefined || !Number.isFinite(n) || !Number.isInteger(n)) return `Enter ${what}`
  if (n < min) return min === 0 ? 'It can\'t be negative' : `It can't be less than ${min}`
  if (n > max) return `It can't be more than ${max}`
  return undefined
}

export function checkUsername(v: string, max = 64): Check {
  const s = v.trim()
  if (!s) return 'Enter a username'
  if (s.length < 2 || s.length > max) return `Use 2 to ${max} characters`
  if (!/^[A-Za-z0-9._@-]+$/.test(s)) return 'Letters, digits, dot, dash, underscore and @ only'
  return undefined
}

export function checkPassword(v: string, min = 8): Check {
  if (!v) return 'Enter a password'
  return v.length >= min ? undefined : `Use at least ${min} characters`
}

export function checkHexColor(v: string): Check {
  return /^#[0-9a-f]{6}$/i.test(v.trim()) ? undefined : 'Use a colour like #7cc8f7'
}

// a port or a range, as routing rules take them
export function checkPortRange(v: string): Check {
  const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(v.trim())
  if (!m) return 'Use a port like 443 or a range like 6881-6889'
  const [a, b] = [Number(m[1]), m[2] ? Number(m[2]) : undefined]
  if (a < 1 || a > 65535 || (b !== undefined && (b < a || b > 65535))) return 'Use a port like 443 or a range like 6881-6889'
  return undefined
}

// the first error found in a list of values, with the offending entry named
export function checkEach(values: string[] | undefined, check: (v: string) => Check): Check {
  for (const v of values ?? []) {
    const e = check(v)
    if (e) return `${v}: ${e}`
  }
  return undefined
}

export function checkRegex(v: string): Check {
  try {
    new RegExp(v)
    return undefined
  }
  catch (e) {
    return `Not a valid regular expression: ${(e as Error).message.replace(/^Invalid regular expression: /, '')}`
  }
}

// drops the undefined entries, so a rule function can list every check unconditionally
export function problems(found: Record<string, Check>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(found)) if (v) out[k] = v
  return out
}
