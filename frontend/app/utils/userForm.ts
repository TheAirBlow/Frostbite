import type { PanelUser, Plan } from '~/types/api'

export interface UserFormState {
  username: string
  status: string
  traffic_limit: number
  reset_strategy: string
  expire_at: string
  duration_days: number
  start_on_first_use: boolean
  on_hold_days: number
  device_limit: number
  ip_limit: number
  tags: string[]
  note: string
  email: string
  telegram_id: number | null
  plan_id: number | null
  squad_ids: number[]
}

export function emptyUserForm(): UserFormState {
  return {
    username: '',
    status: 'active',
    traffic_limit: 0,
    reset_strategy: 'none',
    expire_at: '',
    duration_days: 30,
    start_on_first_use: false,
    on_hold_days: 0,
    device_limit: 0,
    ip_limit: 0,
    tags: [],
    note: '',
    email: '',
    telegram_id: null,
    plan_id: null,
    squad_ids: [],
  }
}

export function formFromUser(u: PanelUser): UserFormState {
  return {
    username: u.username,
    status: u.status === 'limited' || u.status === 'expired' ? u.status : u.status,
    traffic_limit: u.traffic_limit,
    reset_strategy: u.reset_strategy,
    expire_at: u.expire_at ? toDateInput(u.expire_at) : '',
    duration_days: 0,
    start_on_first_use: false,
    on_hold_days: u.on_hold_days,
    device_limit: u.device_limit,
    ip_limit: u.ip_limit,
    tags: [...u.tags],
    note: u.note,
    email: u.email,
    telegram_id: u.telegram_id,
    plan_id: u.plan_id,
    squad_ids: [...u.squad_ids],
  }
}

export function applyPlan(f: UserFormState, p: Plan) {
  f.traffic_limit = p.traffic_limit
  f.reset_strategy = p.reset_strategy
  f.duration_days = p.duration_days
  f.start_on_first_use = p.start_on_first_use
  f.device_limit = p.device_limit
  f.ip_limit = p.ip_limit
  f.squad_ids = [...p.squad_ids]
}

// local calendar date for an <input type="date">
export function toDateInput(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

// the end of the chosen day, so "expires on the 5th" still works all of the 5th
export function fromDateInput(value: string): string | null {
  return value ? new Date(`${value}T23:59:59`).toISOString() : null
}

export function createBody(f: UserFormState): Record<string, unknown> {
  return {
    username: f.username.trim(),
    traffic_limit: f.traffic_limit,
    reset_strategy: f.reset_strategy,
    duration_days: f.expire_at ? 0 : f.duration_days,
    expire_at: fromDateInput(f.expire_at),
    start_on_first_use: f.start_on_first_use,
    on_hold_days: f.on_hold_days,
    device_limit: f.device_limit,
    ip_limit: f.ip_limit,
    tags: f.tags,
    note: f.note,
    email: f.email,
    telegram_id: f.telegram_id,
    plan_id: f.plan_id,
    squad_ids: f.squad_ids,
  }
}

export function updateBody(f: UserFormState): Record<string, unknown> {
  return {
    username: f.username.trim(),
    status: f.status,
    traffic_limit: f.traffic_limit,
    reset_strategy: f.reset_strategy,
    expire_at: fromDateInput(f.expire_at),
    on_hold_days: f.on_hold_days,
    device_limit: f.device_limit,
    ip_limit: f.ip_limit,
    tags: f.tags,
    note: f.note,
    email: f.email,
    telegram_id: f.telegram_id,
    plan_id: f.plan_id,
    squad_ids: f.squad_ids,
  }
}
