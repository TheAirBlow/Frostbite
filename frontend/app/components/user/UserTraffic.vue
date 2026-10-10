<template>
  <div class="flex flex-col gap-4">
    <div class="flex items-center justify-between gap-2">
      <Segmented v-model="range" :options="[{ value: '24h', label: '24h' }, { value: '7d', label: '7d' }, { value: '30d', label: '30d' }]" />
      <p class="text-base-content/60 text-sm">↓ {{ formatBytes(down) }} · ↑ {{ formatBytes(up) }}</p>
    </div>

    <Section :title="$t('Over time')">
      <div class="relative h-56">
        <Transition name="fade"><div v-if="shown" class="skeleton absolute inset-0" /></Transition>
        <EmptyState v-if="!shown && !series.length" icon="fa6-solid:chart-area" :title="$t('Nothing in this period')" />
        <AreaChart v-else-if="series.length" :data="series" :categories="categories" :height="220" :x-formatter="xFormatter" :y-formatter="(v: number) => formatBytes(v)" :curve-type="CurveType.MonotoneX" :duration="0" :tooltip-title-formatter="(d: { hour: string }) => formatDateTime(d.hour)" />
      </div>
    </Section>

    <Section v-if="data?.by_node.length" :title="$t('By node')">
      <div class="flex flex-col gap-2">
        <div v-for="n in data.by_node" :key="n.node_id">
          <div class="flex justify-between text-sm"><span>{{ nodeName(n.node_id) }}</span><span class="text-base-content/60">{{ formatBytes(n.up + n.down) }}</span></div>
          <div class="bg-base-300 mt-1 h-1.5 overflow-hidden rounded-full"><div class="bg-primary h-full rounded-full" :style="{ width: `${((n.up + n.down) / total) * 100}%` }" /></div>
        </div>
      </div>
    </Section>

    <Section :title="$t('Connected from')" hint="Addresses seen on the nodes right now.">
      <div v-if="data?.online_ips.length" class="flex flex-wrap gap-1.5">
        <span v-for="ip in data.online_ips" :key="ip" class="badge badge-soft badge-success font-mono">{{ ip }}</span>
      </div>
      <p v-else class="text-base-content/50 text-sm">{{ $t('Not connected.') }}</p>
    </Section>
  </div>
</template>

<script setup lang="ts">
import { CurveType } from 'vue-chrts'
import type { PanelNode, PanelUser, TrafficPoint } from '~/types/api'

const props = defineProps<{ user: PanelUser }>()
const { trafficRange: range } = storeToRefs(usePreferencesStore())

const { data, pending } = useAsyncData(
  `user-traffic-${props.user.id}`,
  () => useApi<{ series: TrafficPoint[], by_node: { node_id: number, up: number, down: number }[], online_ips: string[] }>(`/users/${props.user.id}/traffic`, { query: { range: range.value } }),
  { watch: [range] },
)
const { data: nodes } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'))
const shown = useDelayedPending(pending)

const series = computed(() => (data.value?.series ?? []).map(p => ({ hour: p.hour, Download: p.down, Upload: p.up })))
const categories = { Download: { name: 'Download', color: 'var(--color-primary)' }, Upload: { name: 'Upload', color: 'var(--color-secondary)' } }
const up = computed(() => (data.value?.series ?? []).reduce((a, p) => a + p.up, 0))
const down = computed(() => (data.value?.series ?? []).reduce((a, p) => a + p.down, 0))
const total = computed(() => (data.value?.by_node ?? []).reduce((a, n) => a + n.up + n.down, 0) || 1)

function nodeName(id: number) {
  return nodes.value?.find(n => n.id === id)?.name ?? `Node ${id}`
}

function xFormatter(_t: number, i?: number) {
  const p = i !== undefined ? series.value[i] : undefined
  if (!p) return ''
  const d = new Date(p.hour)
  return range.value === '24h' ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}
</script>
