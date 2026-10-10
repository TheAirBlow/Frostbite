<template>
  <div>
    <PageHeader :title="t('dash.title')" :subtitle="t('dash.welcome', { name: auth.me?.username ?? '' })">
      <Segmented v-model="range" :options="ranges" />
      <button class="btn btn-primary btn-sm" @click="drawer.open('user-create')">
        <Icon name="fa6-solid:user-plus" size="13" /> {{ t('dash.newUser') }}
      </button>
    </PageHeader>

    <Onboarding v-if="data && !setupDone" :steps="steps" class="mb-5" />

    <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatTile :label="t('dash.users')" :value="data?.users.total ?? '…'" :hint="t('dash.active', { n: data?.users.by_status.active ?? 0 })" icon="fa6-solid:users" />
      <StatTile :label="t('dash.online')" :value="data?.users.online ?? '…'" :hint="t('dash.onlineHint')" icon="fa6-solid:signal" tone="bg-success/15 text-success" />
      <StatTile :label="t('dash.traffic')" :value="formatBytes((data?.traffic.up ?? 0) + (data?.traffic.down ?? 0))" :hint="`↓ ${formatBytes(data?.traffic.down ?? 0)} · ↑ ${formatBytes(data?.traffic.up ?? 0)}`" icon="fa6-solid:arrow-right-arrow-left" tone="bg-secondary/15 text-secondary" />
      <StatTile :label="t('dash.daemons')" :value="data ? `${data.daemons.online}/${data.daemons.total}` : '…'" :hint="data && data.daemons.online < data.daemons.total ? t('dash.someOffline') : t('dash.allConnected')" icon="fa6-solid:server" :tone="data && data.daemons.online < data.daemons.total ? 'bg-warning/15 text-warning' : 'bg-accent/15 text-accent'" />
    </div>

    <div class="mt-4 grid gap-4 xl:grid-cols-3">
      <Section :title="t('dash.traffic')" class="xl:col-span-2">
        <div class="relative h-60">
          <Transition name="fade">
            <div v-if="shown" class="skeleton absolute inset-0" />
          </Transition>
          <EmptyState v-if="!shown && series.length === 0" icon="fa6-solid:chart-area" :title="$t('No traffic yet')" text="Usage shows up here as soon as someone connects." />
          <AreaChart v-else-if="series.length" :data="series" :categories="categories" :height="230" :x-formatter="xFormatter" :y-formatter="(v: number) => formatBytes(v)" :curve-type="CurveType.MonotoneX" :duration="0" :tooltip-title-formatter="titleFormatter" />
        </div>
      </Section>

      <Section :title="t('dash.byStatus')">
        <div v-if="statusSlices.length" class="flex flex-col items-center gap-3">
          <DonutChart :data="statusSlices.map(s => s.value)" :categories="statusCategories" :radius="70" :height="190" :duration="0" />
          <div class="flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs">
            <span v-for="s in statusSlices" :key="s.key" class="flex items-center gap-1.5">
              <span class="size-2 rounded-full" :style="{ background: s.color }" /> {{ t(`status.${s.key}`) }} <b>{{ s.value }}</b>
            </span>
          </div>
        </div>
        <EmptyState v-else icon="fa6-solid:users" :title="$t('No users yet')" />
      </Section>
    </div>

    <div class="mt-4 grid gap-4 xl:grid-cols-3">
      <Section :title="t('dash.nodes')" class="xl:col-span-2">
        <template #actions>
          <NuxtLink to="/nodes" class="btn btn-ghost btn-xs">{{ t('dash.manage') }} <Icon name="fa6-solid:arrow-right" size="11" /></NuxtLink>
        </template>
        <div v-if="nodes?.length" class="flex flex-col gap-2">
          <div v-for="n in nodes" :key="n.id" class="bg-base-100 border-base-300 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border p-3">
            <span class="text-xl">{{ flag(n.country) }}</span>
            <div class="min-w-32 flex-1">
              <p class="font-medium">{{ n.name }}</p>
              <p class="text-base-content/50 font-mono text-xs">{{ n.address }}</p>
            </div>
            <div class="flex items-center gap-3">
              <span v-for="d in n.daemons" :key="d.id" class="flex items-center gap-1.5 text-xs" :title="d.name">
                <Dot :tone="daemonTone(d)" :pulse="d.live.online" /> {{ coreLabels[d.kind] ?? d.kind }}
              </span>
              <span v-if="!n.daemons.length" class="text-base-content/50 text-xs">{{ $t('no daemons') }}</span>
            </div>
            <div v-if="metricsOf(n)" class="flex w-full items-center gap-4 text-xs sm:w-auto">
              <span class="text-base-content/60 w-20">CPU <b class="text-base-content">{{ metricsOf(n)!.cpu.toFixed(0) }}%</b></span>
              <span class="text-base-content/60 w-24">RAM <b class="text-base-content">{{ percent(metricsOf(n)!.mem_used, metricsOf(n)!.mem_total) }}%</b></span>
              <span class="text-base-content/60">↓ <b class="text-base-content">{{ formatSpeed(metricsOf(n)!.net_down) }}</b> ↑ <b class="text-base-content">{{ formatSpeed(metricsOf(n)!.net_up) }}</b></span>
            </div>
          </div>
        </div>
        <EmptyState v-else icon="fa6-solid:server" :title="$t('No nodes yet')" text="A node is a server your users connect to.">
          <button class="btn btn-primary btn-sm" @click="side.open('node')">{{ $t('Add a node') }}</button>
        </EmptyState>
      </Section>

      <Section v-if="data?.traffic.by_node.length" :title="t('dash.byNode')">
        <div class="flex flex-col gap-2.5">
          <div v-for="n in byNode" :key="n.id">
            <div class="flex items-center justify-between text-sm"><span>{{ flag(n.country) }} {{ n.name }}</span><span class="text-base-content/60 text-xs">{{ formatBytes(n.total) }}</span></div>
            <div class="bg-base-300 mt-1 h-1 overflow-hidden rounded-full"><div class="bg-secondary h-full rounded-full" :style="{ width: `${(n.total / byNode[0]!.total) * 100}%` }" /></div>
          </div>
        </div>
      </Section>

      <Section :title="t('dash.topUsers')">
        <div v-if="data?.top.length" class="flex flex-col gap-2.5">
          <button v-for="u in data.top" :key="u.id" class="hover:bg-base-300/40 -mx-2 rounded-lg px-2 py-1 text-left" @click="side.open('user', u.id)">
            <div class="flex items-center justify-between text-sm">
              <span class="truncate">{{ u.username }}</span>
              <span class="text-base-content/60 text-xs">{{ formatBytes(u.total) }}</span>
            </div>
            <div class="bg-base-300 mt-1 h-1 overflow-hidden rounded-full">
              <div class="bg-primary h-full rounded-full" :style="{ width: `${(u.total / data.top[0]!.total) * 100}%` }" />
            </div>
          </button>
        </div>
        <EmptyState v-else icon="fa6-solid:ranking-star" :title="$t('Nobody yet')" />
      </Section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { CurveType } from 'vue-chrts'
import type { Dashboard, Daemon, Inbound, PanelNode, Squad } from '~/types/api'

useHead({ title: 'Dashboard' })

const auth = useAuthStore()
const { t } = useT()
const drawer = useDrawer()
const side = useSideDrawer()
const { dashRange: range } = storeToRefs(usePreferencesStore())

const ranges = [{ value: '24h', label: '24h' }, { value: '7d', label: '7d' }, { value: '30d', label: '30d' }]

const { data, pending, refresh } = useAsyncData(
  'dashboard',
  () => useApi<Dashboard>('/dashboard', { query: { range: range.value } }),
  { watch: [range] },
)
const { data: nodes, refresh: refreshNodes } = useAsyncData('dash-nodes', () => useApi<PanelNode[]>('/nodes'))
const { data: inbounds } = useAsyncData('dash-inbounds', () => useApi<Inbound[]>('/inbounds'))
const { data: squads } = useAsyncData('dash-squads', () => useApi<Squad[]>('/squads'))
const shown = useDelayedPending(pending)

onMounted(() => {
  const t = setInterval(() => {
    refresh()
    refreshNodes()
  }, 15000)
  onScopeDispose(() => clearInterval(t))
})

const series = computed(() => (data.value?.traffic.series ?? []).map(p => ({ hour: p.hour, Download: p.down, Upload: p.up })))
const categories = { Download: { name: 'Download', color: 'var(--color-primary)' }, Upload: { name: 'Upload', color: 'var(--color-secondary)' } }

function xFormatter(_tick: number, i?: number) {
  const p = i !== undefined ? series.value[i] : undefined
  if (!p) return ''
  const d = new Date(p.hour)
  return range.value === '24h' ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function titleFormatter(d: { hour: string }) {
  return formatDateTime(d.hour)
}

const statusColors: Record<string, string> = {
  active: 'var(--color-success)',
  on_hold: 'var(--color-info)',
  limited: 'var(--color-warning)',
  expired: 'var(--color-error)',
  disabled: 'var(--color-neutral)',
}
const statusSlices = computed(() => Object.entries(data.value?.users.by_status ?? {}).filter(([, v]) => v > 0).map(([key, value]) => ({ key, value, color: statusColors[key] ?? 'gray' })))
const statusCategories = computed(() => Object.fromEntries(statusSlices.value.map(s => [statusMeta[s.key]?.label ?? s.key, { name: statusMeta[s.key]?.label ?? s.key, color: s.color }])))

function daemonTone(d: Daemon): 'success' | 'warning' | 'error' | 'muted' {
  if (!d.live.online) return 'muted'
  if (d.last_error) return 'error'
  return d.applied_rev === d.desired_rev ? 'success' : 'warning'
}

function metricsOf(n: PanelNode) {
  return n.daemons.find(d => d.live.metrics)?.live.metrics
}

const steps = computed(() => [
  { done: (nodes.value?.length ?? 0) > 0, title: 'Add a node', text: 'The server users connect to.', action: () => side.open('node'), cta: 'Add node' },
  { done: nodes.value?.some(n => n.daemons.some(d => d.live.online)) ?? false, title: 'Connect a daemon', text: 'Pick a core and run one command on the node.', action: () => navigateTo('/nodes'), cta: 'Open nodes' },
  { done: (inbounds.value?.length ?? 0) > 0, title: 'Create an inbound', text: 'A protocol your users connect with, like VLESS Reality.', action: () => navigateTo('/inbounds'), cta: 'Open inbounds' },
  { done: (squads.value?.some(s => s.inbound_ids.length) ?? false), title: 'Make a squad', text: 'Squads decide which inbounds a user can use.', action: () => navigateTo('/access'), cta: 'Open squads' },
  { done: (data.value?.users.total ?? 0) > 0, title: 'Add your first user', text: 'They get a subscription link that works in every client.', action: () => drawer.open('user-create'), cta: 'New user' },
])
const byNode = computed(() => (data.value?.traffic.by_node ?? [])
  .map(b => ({ id: b.node_id, total: b.up + b.down, name: nodes.value?.find(n => n.id === b.node_id)?.name ?? `Node ${b.node_id}`, country: nodes.value?.find(n => n.id === b.node_id)?.country ?? '' }))
  .sort((a, b) => b.total - a.total))
const setupDone = computed(() => steps.value.every(s => s.done))
</script>
