// Template placeholders for remarks, Turnable destination names and links. Mirrors internal/spec/placeholders.go.

export const placeholderHints: Record<string, string> = {
  node: 'Node name',
  country: 'Two letter country code of the node, like SE',
  flag: 'Flag of the node\'s country, like 🇸🇪',
  country_name: 'Country name in English. {country_name:ru} gives it in another language',
  inbound: 'Inbound tag',
  protocol: 'Protocol, like vless',
  transport: 'Transport, like ws',
  security: 'tls, reality or none',
  user: 'Username',
  host: 'Address the app connects to',
  port: 'Port the app connects to',
  remark: 'Remark of the tunnel\'s host',
  inbound_remark: 'Remark of the inbound the destination leads to, or {remark} for other destinations',
  route: 'Destination id',
  uuid: 'The user\'s UUID',
  password: 'The user\'s password',
  name: 'Destination name, with its placeholders filled in',
}

export const remarkPlaceholders = ['node', 'country', 'flag', 'country_name', 'inbound', 'protocol', 'transport', 'security', 'user', 'host', 'port']
export const routeNamePlaceholders = [...remarkPlaceholders, 'remark', 'inbound_remark', 'route']
export const routeUrlPlaceholders = [...routeNamePlaceholders, 'uuid', 'password', 'name']

// how the reference groups placeholders, in the order it shows them
export const placeholderGroups: { label: string, names: string[] }[] = [
  { label: 'Node', names: ['node', 'country', 'flag', 'country_name'] },
  { label: 'Inbound', names: ['inbound', 'protocol', 'transport', 'security'] },
  { label: 'Connection', names: ['user', 'host', 'port'] },
  { label: 'Destination', names: ['remark', 'inbound_remark', 'route', 'name'] },
  { label: 'Credentials', names: ['uuid', 'password'] },
]

// a template with a placeholder added at the end, a space apart from what is already there
export function appendPlaceholder(tpl: string | undefined, token: string): string {
  if (!tpl) return token
  return /\s$/.test(tpl) ? tpl + token : `${tpl} ${token}`
}

const placeholder = /\{(\w*)(?::([\w-]*))?\}/g

function isLanguage(tag: string): boolean {
  try {
    return Intl.getCanonicalLocales(tag).length === 1
  }
  catch {
    return false
  }
}

// the first placeholder in a template that is unknown or has a wrong argument
export function checkPlaceholders(tpl: string | undefined, allowed: string[]): Check {
  for (const [, key = '', arg = ''] of (tpl ?? '').matchAll(placeholder)) {
    if (!allowed.includes(key)) return `Unknown placeholder {${key}}`
    if (key === 'country_name') {
      if (arg && !isLanguage(arg)) return `{country_name:${arg}} needs a language code, like {country_name:ru}`
    }
    else if (key === 'flag') {
      if (arg) return '{flag} takes no argument'
    }
    else if (arg && arg !== 'upper' && arg !== 'lower') {
      return `{${key}:${arg}}: use upper or lower after the colon`
    }
  }
  return undefined
}
