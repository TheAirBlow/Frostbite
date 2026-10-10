<template>
  <div>
    <PageHeader :title="$t('Nodes')" subtitle="Servers your users connect to, and the daemons running on them.">
      <button class="btn btn-primary btn-sm" @click="side.open('node')"><Icon name="fa6-solid:plus" size="13" /> {{ $t('Add node') }}</button>
    </PageHeader>

    <Skeleton v-if="shown" :rows="3" :height="190" />
    <div v-else-if="nodes?.length" class="grid gap-4 xl:grid-cols-2">
      <NodeCard v-for="n in nodes" :key="n.id" :node="n" @add-daemon="addFor = n" @logs="logsFor = $event" @preview="previewFor = $event" @changed="refresh" />
    </div>
    <div v-else class="surface">
      <EmptyState icon="fa6-solid:server" :title="$t('No nodes yet')" text="Add the first server. You can have as many as you like, each running Xray, sing-box or both.">
        <button class="btn btn-primary btn-sm" @click="side.open('node')">{{ $t('Add a node') }}</button>
      </EmptyState>
    </div>

    <AddDaemonModal v-if="addFor" :node="addFor" @close="addFor = null" @created="refresh" />
    <DaemonLogs v-if="logsFor" :daemon="logsFor" @close="logsFor = null" />
    <ConfigPreview v-if="previewFor" :daemon="previewFor" @close="previewFor = null" />
  </div>
</template>

<script setup lang="ts">
import type { Daemon, PanelNode } from '~/types/api'

useHead({ title: 'Nodes' })
const side = useSideDrawer()

const { data: nodes, pending, refresh } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'))
const shown = useDelayedPending(computed(() => pending.value && !nodes.value))
usePolling(async () => {
  if (!document.hidden) await refresh()
  return null
}, 8000)

const addFor = ref<PanelNode | null>(null)
const logsFor = ref<Daemon | null>(null)
const previewFor = ref<Daemon | null>(null)
</script>
