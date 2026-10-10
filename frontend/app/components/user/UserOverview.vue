<template>
  <div class="flex flex-col gap-4">
    <div class="surface flex flex-wrap items-center gap-5 p-4">
      <div class="relative grid size-28 shrink-0 place-items-center rounded-full" :style="ring">
        <div class="bg-base-200 grid size-[5.6rem] place-items-center rounded-full text-center">
          <div>
            <p class="font-display text-2xl leading-none font-semibold">{{ user.traffic_limit ? `${pct}%` : '∞' }}</p>
            <p class="text-base-content/50 mt-0.5 text-[11px]">{{ $t('used') }}</p>
          </div>
        </div>
      </div>
      <div class="grid min-w-0 flex-1 grid-cols-2 gap-x-4 gap-y-3 text-sm">
        <div><p class="text-base-content/50 text-xs">{{ $t('Status') }}</p><StatusBadge :status="user.status" class="mt-1" /></div>
        <div><p class="text-base-content/50 text-xs">{{ $t('Online') }}</p><p class="mt-1 flex items-center gap-1.5"><Dot :tone="user.online ? 'success' : 'muted'" :pulse="user.online" /> {{ user.online ? 'Connected' : formatRelative(user.online_at) }}</p></div>
        <div><p class="text-base-content/50 text-xs">{{ $t('This period') }}</p><p class="mt-1 font-medium">{{ formatBytes(user.traffic_used) }}<span v-if="user.traffic_limit" class="text-base-content/50 font-normal"> / {{ formatBytes(user.traffic_limit) }}</span></p></div>
        <div><p class="text-base-content/50 text-xs">{{ $t('All time') }}</p><p class="mt-1 font-medium">{{ formatBytes(user.traffic_lifetime) }}</p></div>
      </div>
    </div>

    <div v-if="alert" class="alert alert-soft" :class="alert.cls"><Icon :name="alert.icon" size="15" /><span class="text-sm">{{ alert.text }}</span></div>

    <Section :title="$t('Validity')">
      <div class="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p class="font-display text-2xl font-semibold">{{ validity }}</p>
          <p class="text-base-content/60 text-sm">{{ user.expire_at ? `until ${formatDateTime(user.expire_at)}` : user.status === 'on_hold' ? 'The clock starts at their first connection.' : 'Never expires.' }}</p>
          <p class="text-base-content/50 mt-1 text-xs">Traffic resets: {{ resetLabels[user.reset_strategy]?.toLowerCase() }}<template v-if="user.reset_strategy !== 'none'"> · last {{ formatRelative(user.last_reset) }}</template></p>
        </div>
        <div class="flex flex-wrap gap-1">
          <button v-for="d in [7, 30, 90, 365]" :key="d" class="btn btn-xs rounded-full" :disabled="busy" @click="act('extend', { days: d }, `Extended by ${d} days.`)">+{{ d }}d</button>
        </div>
      </div>
    </Section>

    <Section :title="$t('Subscription')" hint="One link that works in every client.">
      <div class="flex flex-col gap-3 sm:flex-row">
        <QrCode :value="user.sub_url" :size="150" class="shrink-0 self-center" />
        <div class="min-w-0 flex-1">
          <div class="bg-base-100 border-base-300 flex items-center gap-1 rounded-lg border py-1 pr-1 pl-3">
            <span class="min-w-0 flex-1 truncate font-mono text-xs">{{ user.sub_url }}</span>
            <CopyButton :value="user.sub_url" label="Copy subscription link" />
          </div>
          <div class="mt-2 flex flex-wrap gap-1.5">
            <a :href="`/u/${user.sub_token}`" target="_blank" class="btn btn-sm"><Icon name="fa6-solid:arrow-up-right-from-square" size="11" /> {{ $t('Open user page') }}</a>
            <button class="btn btn-sm" @click="emit('tab', 'links')"><Icon name="fa6-solid:link" size="11" /> {{ $t('Connections') }}</button>
          </div>
          <p v-if="user.sub_last_at" class="text-base-content/50 mt-2 text-xs">Last fetched {{ formatRelative(user.sub_last_at) }} by <span class="font-mono">{{ user.sub_last_ua || 'unknown' }}</span></p>
        </div>
      </div>
    </Section>

    <Section :title="$t('Actions')">
      <div class="flex flex-wrap gap-2">
        <button class="btn btn-sm" :disabled="busy" @click="act('reset_traffic', {}, 'Traffic reset.')"><Icon name="fa6-solid:rotate-left" size="12" /> {{ $t('Reset traffic') }}</button>
        <button v-if="user.status !== 'disabled'" class="btn btn-sm" :disabled="busy" @click="act('disable', {}, 'User disabled.')"><Icon name="fa6-solid:pause" size="12" /> {{ $t('Disable') }}</button>
        <button v-else class="btn btn-sm btn-success" :disabled="busy" @click="act('enable', {}, 'User enabled.')"><Icon name="fa6-solid:play" size="12" /> {{ $t('Enable') }}</button>
        <ConfirmButton class="btn btn-sm" confirm-label="New link, old one dies" @confirmed="rotate('sub')"><Icon name="fa6-solid:link-slash" size="12" /> {{ $t('New subscription link') }}</ConfirmButton>
        <ConfirmButton class="btn btn-sm" confirm-label="Everyone reconnects" @confirmed="rotate('secrets')"><Icon name="fa6-solid:key" size="12" /> {{ $t('New credentials') }}</ConfirmButton>
        <ConfirmButton class="btn btn-sm btn-ghost text-error ml-auto" confirm-label="Delete for good?" @confirmed="remove"><Icon name="fa6-solid:trash" size="12" /> {{ $t('Delete') }}</ConfirmButton>
      </div>
    </Section>
  </div>
</template>

<script setup lang="ts">
import type { PanelUser } from '~/types/api'

const props = defineProps<{ user: PanelUser }>()
const emit = defineEmits<{ changed: [], deleted: [], tab: [t: string] }>()
const toast = useToast()

const pct = computed(() => percent(props.user.traffic_used, props.user.traffic_limit))
const ring = computed(() => ({
  background: props.user.traffic_limit
    ? `conic-gradient(${pct.value >= 95 ? 'var(--color-error)' : pct.value >= 80 ? 'var(--color-warning)' : 'var(--color-primary)'} ${pct.value}%, var(--color-base-300) 0)`
    : 'conic-gradient(color-mix(in oklab, var(--color-primary) 35%, transparent) 100%, transparent 0)',
}))

const validity = computed(() => {
  const d = daysLeft(props.user.expire_at)
  if (d === null) return props.user.status === 'on_hold' ? 'On hold' : 'Unlimited'
  if (d < 0) return `Expired ${-d} days ago`
  return d === 0 ? 'Expires today' : `${d} days left`
})

const alert = computed(() => {
  const u = props.user
  if (u.status === 'limited') return { cls: 'alert-warning', icon: 'fa6-solid:gauge-high', text: 'The traffic limit was reached. Reset the traffic or raise the limit to bring them back.' }
  if (u.status === 'expired') return { cls: 'alert-error', icon: 'fa6-solid:calendar-xmark', text: 'This user expired. Extend them below.' }
  if (u.blocked_until && new Date(u.blocked_until) > new Date()) return { cls: 'alert-warning', icon: 'fa6-solid:shield-halved', text: `Cut off until ${formatDateTime(u.blocked_until)} for using more IPs than allowed.` }
  return null
})

const { loading: busy, run: act } = useAsyncAction(async (action: string, extra: Record<string, unknown>, message: string) => {
  await useApi('/users/bulk', { method: 'POST', body: { action, ids: [props.user.id], ...extra } })
  toast.success(message)
  emit('changed')
})

const { run: rotate } = useAsyncAction(async (what: string) => {
  await useApi(`/users/${props.user.id}/rotate`, { method: 'POST', body: { what } })
  emit('changed')
}, 'Done.')

const { run: remove } = useAsyncAction(async () => {
  await useApi('/users/bulk', { method: 'POST', body: { action: 'delete', ids: [props.user.id] } })
  await refreshNuxtData('users')
  emit('deleted')
}, 'User deleted.')
</script>
