<template>
  <section class="surface p-4" :class="{ 'opacity-60': !node.enabled }">
    <div class="flex items-start gap-3">
      <span class="text-3xl leading-none">{{ flag(node.country) }}</span>
      <div class="min-w-0 flex-1">
        <h3 class="font-display truncate text-xl font-semibold">{{ node.name }}</h3>
        <p class="text-base-content/60 flex items-center gap-1 font-mono text-xs">{{ node.address }} <CopyButton :value="node.address" /></p>
        <div class="mt-1.5 flex flex-wrap gap-1.5">
          <span v-if="!node.enabled" class="badge badge-sm badge-neutral">{{ $t('disabled') }}</span>
          <span v-if="node.traffic_multiplier !== 1" class="badge badge-sm badge-warning badge-soft" :title="$t('Traffic is multiplied by this before it counts against users')">×{{ node.traffic_multiplier }}</span>
          <span v-for="t in node.tags" :key="t" class="badge badge-sm badge-ghost">{{ t }}</span>
        </div>
      </div>
      <button class="btn btn-ghost btn-sm btn-square" :title="$t('Edit node')" @click="side.open('node', node.id)"><Icon name="fa6-solid:pen" size="13" /></button>
    </div>

    <div v-if="node.traffic_used || node.traffic_limit" class="mt-3">
      <UsageBar :used="node.traffic_used" :limit="node.traffic_limit" />
    </div>

    <div class="mt-4 flex flex-col gap-2">
      <div v-for="d in node.daemons" :key="d.id" class="bg-base-100 border-base-300 rounded-xl border p-3" :class="{ 'opacity-60': !d.enabled }">
        <div class="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <Dot :tone="tone(d)" :pulse="d.live.online && tone(d) === 'success'" />
          <div class="min-w-0 flex-1">
            <p class="flex flex-wrap items-center gap-x-2 font-medium">
              {{ d.name }}
              <span class="badge badge-sm badge-primary badge-soft">{{ coreLabels[d.kind] ?? d.kind }}</span>
              <span v-if="!d.enabled" class="badge badge-sm badge-neutral">{{ $t('disabled') }}</span>
            </p>
            <p class="text-base-content/50 text-xs">
              <template v-if="d.live.online">{{ d.core_version }} · up {{ since(d) }} · {{ syncText(d) }}</template>
              <template v-else>{{ d.last_seen ? `offline, seen ${formatRelative(d.last_seen)}` : 'waiting for the first connection' }}</template>
            </p>
          </div>
          <div class="dropdown dropdown-end">
            <button tabindex="0" class="btn btn-ghost btn-xs btn-square"><Icon name="fa6-solid:ellipsis-vertical" size="13" /></button>
            <ul tabindex="0" class="dropdown-content menu bg-base-200 border-base-300 rounded-box z-30 w-52 border p-2 shadow-xl">
              <li><button @click="emit('preview', d)"><Icon name="fa6-solid:code" size="12" /> {{ $t('Show config') }}</button></li>
              <li><button :disabled="!d.live.online" @click="emit('logs', d)"><Icon name="fa6-solid:terminal" size="12" /> {{ $t('Logs') }}</button></li>
              <li><button :disabled="!d.live.online" @click="restart(d.id)"><Icon name="fa6-solid:rotate" size="12" /> {{ $t('Restart core') }}</button></li>
              <li><button @click="side.open('daemon', d.id)"><Icon name="fa6-solid:sliders" size="12" /> {{ $t('Settings') }}</button></li>
              <li><button @click="rotate(d)"><Icon name="fa6-solid:key" size="12" /> {{ $t('New token') }}</button></li>
              <li><ConfirmButton class="text-error" confirm-label="Delete it?" @confirmed="remove(d.id)"><Icon name="fa6-solid:trash" size="12" /> {{ $t('Delete') }}</ConfirmButton></li>
            </ul>
          </div>
        </div>

        <p v-for="c in (d.live.certs ?? []).filter(x => !x.ok)" :key="c.domain" class="text-warning bg-warning/10 mt-2 rounded-lg px-2.5 py-1.5 text-xs">
          <Icon name="fa6-solid:certificate" size="11" /> {{ c.domain }}: {{ c.placeholder ? 'waiting for a real certificate' : 'certificate problem' }}<template v-if="c.error">: {{ c.error }}</template>
        </p>
        <p v-if="d.last_error" class="text-error bg-error/10 mt-2 rounded-lg px-2.5 py-1.5 font-mono text-xs break-words">{{ d.last_error }}</p>

        <div v-if="d.live.metrics" class="mt-2.5 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs sm:grid-cols-4">
          <div><p class="text-base-content/50">CPU</p><progress class="progress progress-primary h-1.5 w-full" :value="d.live.metrics.cpu" max="100" /><p>{{ d.live.metrics.cpu.toFixed(0) }}%</p></div>
          <div><p class="text-base-content/50">{{ $t('Memory') }}</p><progress class="progress progress-secondary h-1.5 w-full" :value="d.live.metrics.mem_used" :max="d.live.metrics.mem_total || 1" /><p>{{ formatBytes(d.live.metrics.mem_used) }}</p></div>
          <div><p class="text-base-content/50">{{ $t('Network') }}</p><p class="mt-2">↓ {{ formatSpeed(d.live.metrics.net_down) }}</p><p>↑ {{ formatSpeed(d.live.metrics.net_up) }}</p></div>
          <div><p class="text-base-content/50">{{ $t('Host') }}</p><p class="mt-2">{{ d.host_info.hostname }}</p><p class="text-base-content/50">{{ formatUptime(d.live.metrics.uptime) }}</p></div>
        </div>
      </div>

      <p v-if="!node.daemons.length" class="text-base-content/50 px-1 py-2 text-sm">{{ $t('Nothing runs here yet. Add a daemon to start serving traffic.') }}</p>
    </div>

    <button class="btn btn-sm btn-outline mt-3" @click="emit('add-daemon')"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add daemon') }}</button>

    <AppModal v-if="enrollment" :title="$t('New token')" :subtitle="enrollment.daemon.name" max-width="max-w-xl" @close="enrollment = null">
      <EnrollPanel :enrollment="enrollment.data" :kind="enrollment.daemon.kind" />
    </AppModal>
  </section>
</template>

<script setup lang="ts">
import type { Daemon, PanelNode } from '~/types/api'

defineProps<{ node: PanelNode }>()
const emit = defineEmits<{ 'add-daemon': [], logs: [d: Daemon], preview: [d: Daemon], changed: [] }>()
const side = useSideDrawer()
const toast = useToast()

function tone(d: Daemon): 'success' | 'warning' | 'error' | 'muted' {
  if (!d.live.online) return 'muted'
  if (d.last_error) return 'error'
  return d.applied_rev === d.desired_rev ? 'success' : 'warning'
}

function syncText(d: Daemon) {
  if (d.last_error) return 'rejected the last config'
  return d.applied_rev === d.desired_rev ? `in sync (r${d.applied_rev})` : `applying r${d.desired_rev}…`
}

function since(d: Daemon) {
  return d.live.since ? formatRelative(d.live.since).replace(' ago', '').replace('in ', '') : ''
}

const { run: restart } = useAsyncAction(async (id: number) => {
  await useApi(`/daemons/${id}/restart`, { method: 'POST' })
}, 'Restarted.')

const { run: remove } = useAsyncAction(async (id: number) => {
  await useApi(`/daemons/${id}`, { method: 'DELETE' })
  emit('changed')
}, 'Daemon deleted.')

const enrollment = ref<{ daemon: Daemon, data: { token: string, env: string, command: string } } | null>(null)
async function rotate(d: Daemon) {
  try {
    enrollment.value = { daemon: d, data: await useApi('/daemons/' + d.id + '/rotate', { method: 'POST' }) }
  }
  catch (e) {
    toast.error(errorMessage(e))
  }
}
</script>
