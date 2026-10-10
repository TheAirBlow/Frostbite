export interface ApiErrorBody {
  title: string
  detail: string
}

export type Role = 'owner' | 'admin' | 'reseller'

export interface Admin {
  id: number
  username: string
  role: Role
  enabled: boolean
  user_quota: number | null
  traffic_quota: number | null
  note: string
  created_at: string
}

export interface ApiToken {
  id: number
  name: string
  last_used_at: string | null
  created_at: string
  token?: string
}

export interface HostInfo {
  hostname?: string
  os?: string
  arch?: string
  cpus?: number
  mem_total?: number
  kernel?: string
}

export interface Metrics {
  cpu: number
  mem_used: number
  mem_total: number
  disk_used: number
  disk_total: number
  net_up: number
  net_down: number
  load1: number
  uptime: number
}

export interface CertStatus {
  domain: string
  ok: boolean
  placeholder: boolean
  error?: string
  expires: string
}

export interface Live {
  online: boolean
  certs?: CertStatus[]
  since?: string
  metrics?: Metrics
  metrics_at?: string
}

export interface Daemon {
  id: number
  node_id: number
  kind: string
  name: string
  enabled: boolean
  desired_rev: number
  applied_rev: number
  last_error: string
  last_seen: string | null
  core_version: string
  agent_version: string
  host_info: HostInfo
  log_level: string
  dns_servers: string[]
  dns_strategy: string
  final_outbound: string
  raw_patch: Record<string, unknown> | null
  edge_listen: string[]
  edge_default: string
  live: Live
}

export interface PanelNode {
  id: number
  name: string
  address: string
  country: string
  tags: string[]
  traffic_multiplier: number
  traffic_limit: number
  traffic_used: number
  note: string
  enabled: boolean
  sort: number
  created_at: string
  daemons: Daemon[]
}

export interface Enrollment {
  token: string
  env: string
  command: string
}

export interface CoreInfo {
  kind: string
  display_name: string
  caps: {
    protocols: string[]
    transports: string[]
    securities: string[]
    outbounds: string[]
    hot_users: boolean
  }
}

export interface Transport {
  type: string
  path?: string
  host?: string
  service_name?: string
  mode?: string
  headers?: Record<string, string>
  early_data?: number
  kcp_seed?: string
}

export interface Reality {
  dest: string
  server_names: string[]
  private_key?: string
  public_key?: string
  short_ids: string[]
  spider_x?: string
  xver?: number
}

export interface Security {
  type: string
  sni?: string
  alpn?: string[]
  fingerprint?: string
  insecure?: boolean
  cert_path?: string
  key_path?: string
  ech_key?: string
  ech_config?: string
  reality?: Reality | null
  acme?: { domain: string, email?: string } | null
}

export interface Mux {
  enabled: boolean
  protocol?: string
  concurrency?: number
  padding?: boolean
}

export interface Fragment {
  enabled: boolean
  packets?: string
  length?: string
  interval?: string
}

export type Options = Record<string, unknown> & {
  mux?: Mux | null
  fragment?: Fragment | null
}

export interface Sniffing {
  enabled: boolean
  route_only: boolean
  dest_override: boolean
}

export interface Forward {
  address: string
  port: number
  network: string
}

export interface Host {
  id: number
  inbound_id: number
  bridge_inbound_id: number | null
  remark: string
  address: string
  port: number | null
  sni: string
  host: string
  path: string
  alpn: string[]
  fingerprint: string
  insecure: boolean
  mux: Mux | null
  fragment: Fragment | null
  enabled: boolean
  sort: number
}

export interface Inbound {
  id: number
  daemon_id: number
  tag: string
  remark: string
  protocol: string
  listen: string
  port: number
  transport: Transport
  security: Security
  options: Options
  sniffing: Sniffing
  forward: Forward | null
  raw_patch: Record<string, unknown> | null
  enabled: boolean
  system: boolean
  sort: number
  edge_daemon_id: number | null
  edge_sni: string[]
  hosts: Host[]
}

export interface Upstream {
  name: string
  protocol: string
  address: string
  port: number
  uuid?: string
  password?: string
  username?: string
  transport: Transport
  security: Security
  options: Options
}

export interface Outbound {
  id: number
  daemon_id: number
  tag: string
  kind: 'direct' | 'block' | 'proxy' | 'warp'
  upstream: Upstream | null
  target_inbound_id: number | null
  interface: string
  strategy: string
  sort: number
}

export interface RuleMatch {
  inbound_tags?: string[]
  users?: string[]
  domain?: string[]
  domain_suffix?: string[]
  domain_keyword?: string[]
  geosite?: string[]
  geoip?: string[]
  ip_cidr?: string[]
  port?: string[]
  network?: string
  protocol?: string[]
}

export interface Rule {
  id: number
  daemon_id: number | null
  name: string
  match: RuleMatch
  outbound: string
  enabled: boolean
  sort: number
}

export interface RuleTemplate {
  id: string
  label: string
  description?: string
  match: RuleMatch
  outbound: string
}

export interface RoutingSettings {
  block_bittorrent: boolean
  block_private: boolean
  block_ads: boolean
  block_quic: boolean
  direct_domains: string[]
}

export interface SubSettings {
  title: string
  support_url: string
  web_page_url: string
  announce: string
  update_hours: number
  default_format: string
  notice_profiles: boolean
  sort_by_country: boolean
  hide_bridges: boolean
  logo_url: string
  accent: string
  footer: string
}

export interface PresetParam {
  key: string
  label: string
  hint?: string
  default?: string
  kind: 'string' | 'number'
}

export interface Preset {
  id: string
  label: string
  description: string
  group: string
  cores: string[]
  params: PresetParam[]
}

export interface SchemaField {
  path: string
  label: string
  type: 'string' | 'number' | 'bool' | 'list' | 'map'
  hint?: string
  options?: string[]
  show?: Record<string, string[]>
  advanced?: boolean
}

export type Schema = Record<string, SchemaField[]>

export interface Squad {
  id: number
  name: string
  note: string
  inbound_ids: number[]
  users: number
}

export interface Plan {
  id: number
  name: string
  traffic_limit: number
  duration_days: number
  reset_strategy: string
  start_on_first_use: boolean
  device_limit: number
  ip_limit: number
  squad_ids: number[]
  note: string
}

export type UserStatus = 'active' | 'disabled' | 'limited' | 'expired' | 'on_hold'

export interface PanelUser {
  id: number
  username: string
  uuid: string
  password: string
  sub_token: string
  status: UserStatus
  traffic_limit: number
  traffic_used: number
  traffic_lifetime: number
  reset_strategy: string
  last_reset: string
  expire_at: string | null
  on_hold_days: number
  device_limit: number
  ip_limit: number
  tags: string[]
  note: string
  email: string
  telegram_id: number | null
  plan_id: number | null
  owner_id: number | null
  online_at: string | null
  blocked_until: string | null
  sub_last_at: string | null
  sub_last_ua: string
  created_at: string
  squad_ids: number[]
  online: boolean
  sub_url: string
}

export interface UserPage {
  items: PanelUser[]
  total: number
}

export interface TrafficPoint {
  hour: string
  up: number
  down: number
}

export interface UserLink {
  name: string
  node: string
  country: string
  protocol: string
  bridge: boolean
  link: string
  config?: string
}

export interface UserDevice {
  id: number
  hwid: string
  platform: string
  model: string
  os_version: string
  user_agent: string
  first_seen: string
  last_seen: string
}

export interface Dashboard {
  users: { total: number, online: number, by_status: Record<string, number> }
  traffic: { series: TrafficPoint[], up: number, down: number, by_node: { node_id: number, up: number, down: number }[] }
  top: { id: number, username: string, total: number }[]
  daemons: { total: number, online: number }
}

export interface TopologyInbound {
  id: number
  tag: string
  protocol: string
  port: number
  relay: boolean
}

export interface TopologyDaemon {
  id: number
  kind: string
  name: string
  online: boolean
  inbounds: TopologyInbound[]
}

export interface TopologyNode {
  id: number
  name: string
  address: string
  country: string
  daemons: TopologyDaemon[]
}

export interface TopologyEdge {
  kind: 'relay' | 'chain' | 'custom'
  from_node: number
  to_node?: number
  from_inbound?: number
  to_inbound?: number
  label: string
  custom?: string
}

export interface Topology {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

export interface SubTemplate {
  id: number
  name: string
  format: string
  patch: Record<string, unknown>
}

export interface SubRule {
  id: number
  name: string
  ua_regex: string
  format: string
  template_id: number | null
  enabled: boolean
  sort: number
}

export interface AuditEntry {
  id: number
  admin_name: string
  action: string
  target: string
  detail: Record<string, unknown>
  created_at: string
}

export interface PortalApp {
  id: string
  name: string
  platforms: string[]
  import?: string
  download: string
  format: string
}

export interface Portal {
  user: {
    username: string
    status: UserStatus
    traffic_used: number
    traffic_limit: number
    expire_at: string | null
    reset_strategy: string
    last_reset: string
    on_hold_days: number
    device_limit: number
  }
  sub_url: string
  formats: Record<string, string>
  links: UserLink[]
  apps: PortalApp[]
  title: string
  support_url: string
  announce: string
  telegram_bot: string
  token: string
  brand: { logo_url: string, accent: string, footer: string }
}

export interface CommandResult {
  id: number
  ok: boolean
  output?: string
  error?: string
}

export interface Webhook {
  url: string
  secret: string
  events: string[]
  enabled: boolean
}

export interface NotificationSettings {
  webhooks: Webhook[]
  telegram: {
    enabled: boolean
    token: string
    admin_ids: number[]
    events: string[]
    notify_users: boolean
    api_base: string
  }
  expire_days: number[]
  usage_percent: number[]
  token_set: boolean
}

export interface DeliveryResult {
  target: string
  ok: boolean
  error?: string
}

export interface BackupFile {
  name: string
  size: number
  created: string
}

export interface BackupSchedule {
  enabled: boolean
  interval_hours: number
  keep: number
  history: boolean
}

export interface WarpStatus {
  registered: boolean
  type?: string
  license?: string
  address_v4?: string
  address_v6?: string
  created_at?: string
}

export interface ImportReport {
  panel?: string
  created: number
  dry_run: boolean
  problems: { line: number, username: string, reason: string }[]
  sample: { username: string, traffic_limit: number, traffic_used: number, expire_at: string | null, note: string }[]
}

export interface Quota {
  users: number
  user_quota: number | null
  traffic_allocated: number
  traffic_used: number
  traffic_quota: number | null
}
