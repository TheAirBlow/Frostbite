<template>
  <div>
    <PageHeader :title="$t('Inbounds')" subtitle="The protocols and ports your users connect with.">
      <button class="btn btn-primary btn-sm" :disabled="!daemons.some(d => d.kind !== 'edge')" @click="picker = true"><Icon name="fa6-solid:plus" size="13" /> {{ $t('New inbound') }}</button>
    </PageHeader>

    <Skeleton v-if="shown" :rows="3" :height="120" />
    <div v-else-if="groups.length" class="surface overflow-x-auto p-0">
      <table class="table whitespace-nowrap">
        <tbody v-for="g in groups" :key="g.daemon.id" class="border-base-300 border-b last:border-b-0">
          <tr class="bg-base-300/40">
            <td colspan="6" class="px-4 py-3">
              <div class="flex w-0 min-w-full items-center gap-3">
                <span class="text-xl">{{ flag(g.node.country) }}</span>
                <div class="min-w-0 flex-1">
                  <p class="flex items-center gap-2 font-medium"><span class="truncate">{{ g.node.name }}</span><span class="badge badge-sm badge-primary badge-soft shrink-0">{{ coreLabels[g.daemon.kind] ?? g.daemon.kind }}</span></p>
                  <p class="text-base-content/50 flex items-center gap-1.5 text-xs"><Dot :tone="g.daemon.live.online ? 'success' : 'muted'" /> {{ g.daemon.live.online ? $t('connected') : $t('offline') }} · {{ t('{n} inbounds', { n: g.inbounds.length }) }}</p>
                </div>
                <button v-if="g.daemon.kind !== 'edge'" class="btn btn-sm btn-soft btn-primary" @click="picker = g.daemon.id"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add') }}</button>
                <button v-else class="btn btn-sm" @click="side.open('daemon', g.daemon.id)"><Icon name="fa6-solid:sliders" size="12" /> {{ $t('Edge settings') }}</button>
              </div>
            </td>
          </tr>
          <tr v-for="i in g.inbounds" :key="i.id" class="border-base-300 hover:bg-base-300/30 cursor-pointer" :class="{ 'opacity-55': !i.enabled }" @click="side.open('inbound', i.id)">
            <td class="w-0 ps-4 max-sm:hidden"><span class="badge badge-primary badge-soft w-28 justify-center">{{ protocolLabels[i.protocol] ?? i.protocol }}</span></td>
            <td class="w-full max-w-0 max-sm:ps-4">
              <p class="truncate font-medium">{{ i.remark || i.tag }}</p>
              <p class="text-base-content/50 truncate font-mono text-xs">{{ i.tag }}</p>
              <p class="text-base-content/60 mt-1 flex items-center gap-1.5 text-xs sm:hidden">
                {{ protocolLabels[i.protocol] ?? i.protocol }} · {{ i.protocol === 'forward' ? `${i.forward?.address}:${i.forward?.port}` : (i.transport.type || 'tcp') }}<template v-if="i.security.type && i.security.type !== 'none'"> · {{ i.security.type }}</template> · <span class="font-mono">:{{ i.port }}</span>
              </p>
            </td>
            <td class="max-sm:hidden">
              <div class="flex items-center gap-1.5">
                <span v-if="i.protocol !== 'forward'" class="badge badge-sm badge-ghost" :title="$t('Transport')">{{ i.transport.type || 'tcp' }}</span>
                <span v-if="i.security.type && i.security.type !== 'none'" class="badge badge-sm" :class="i.security.type === 'reality' ? 'badge-secondary badge-soft' : 'badge-accent badge-soft'">{{ i.security.type }}</span>
                <span v-if="i.protocol === 'forward'" class="badge badge-sm badge-info badge-soft"><Icon name="fa6-solid:arrow-right" size="9" /> {{ i.forward?.address }}:{{ i.forward?.port }}</span>
              </div>
            </td>
            <td class="text-right font-mono text-sm max-sm:hidden" :title="$t('Port')"><span class="text-base-content/50 me-1 font-sans text-xs">{{ $t('port') }}</span>{{ i.port }}</td>
            <td class="text-base-content/50 text-right text-xs max-md:hidden">{{ t('{n} hosts', { n: i.hosts.length }) }}<template v-if="i.hosts.some(h => h.bridge_inbound_id)"> · {{ $t('relay') }}</template></td>
            <td class="w-0 pe-4"><input type="checkbox" class="toggle toggle-sm toggle-primary" :checked="i.enabled" :aria-label="`Enable ${i.tag}`" @click.stop @change="toggle(i)"></td>
          </tr>
          <tr v-if="g.daemon.kind === 'edge'">
            <td colspan="6" class="px-4 py-3 text-sm whitespace-normal">
              <div class="w-0 min-w-full">
                <p class="text-base-content/60 mb-2 text-xs">{{ $t('Listens on {ports} and hands each connection to the inbound that owns its server name.', { ports: g.daemon.edge_listen.join(', ') }) }}</p>
                <div v-if="fronted(g.daemon.id).length" class="flex flex-col gap-1.5">
                  <button v-for="i in fronted(g.daemon.id)" :key="i.id" class="bg-base-100 border-base-300 hover:border-primary/50 flex items-center gap-3 rounded-lg border px-3 py-2 text-left transition" @click="side.open('inbound', i.id)">
                    <Icon name="fa6-solid:arrow-right" size="11" class="text-primary" /><span class="font-medium">{{ i.remark || i.tag }}</span><span class="text-base-content/50 truncate font-mono text-xs">{{ edgeNamesOf(i).join(', ') }}</span>
                  </button>
                </div>
                <p v-else class="text-base-content/50">{{ $t('Nothing is behind this edge yet. Open an inbound on this node and choose it under "Shared port".') }}</p>
                <p v-if="g.daemon.edge_default" class="text-base-content/50 mt-2 text-xs">{{ $t('Everything else goes to {target}.', { target: g.daemon.edge_default }) }}</p>
              </div>
            </td>
          </tr>
          <tr v-else-if="!g.inbounds.length">
            <td colspan="6" class="text-base-content/50 px-4 py-4 text-center text-sm whitespace-normal"><p class="w-0 min-w-full">{{ $t('Nothing here yet. Add an inbound to give this daemon something to serve.') }}</p></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="surface">
      <EmptyState icon="fa6-solid:plug" :title="daemons.length ? 'No inbounds yet' : 'Add a daemon first'" :text="daemons.length ? 'Pick a recipe like VLESS Reality.' : 'Inbounds live on a daemon, which lives on a node.'">
        <button v-if="daemons.length" class="btn btn-soft btn-primary btn-sm" @click="picker = true">{{ $t('New inbound') }}</button>
        <NuxtLink v-else to="/nodes" class="btn btn-soft btn-primary btn-sm">{{ $t('Go to nodes') }}</NuxtLink>
      </EmptyState>
    </div>

    <PresetPicker v-if="picker" :nodes="nodes ?? []" :daemon-id="typeof picker === 'number' ? picker : null" @close="picker = false" @created="onCreated" />
  </div>
</template>

<script setup lang="ts">
import type { Daemon, Inbound, PanelNode } from '~/types/api'

useHead({ title: 'Inbounds' })
const route = useRoute()
const { t } = useT()
const side = useSideDrawer()

const { data: nodes, pending: p1 } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'))
const { data: inbounds, pending: p2, refresh } = useAsyncData('inbounds', () => useApi<Inbound[]>('/inbounds'))
const shown = useDelayedPending(computed(() => (p1.value || p2.value) && !inbounds.value))
const picker = ref<boolean | number>(false)

const daemons = computed(() => (nodes.value ?? []).flatMap(n => n.daemons))
const fronted = (edgeId: number) => (inbounds.value ?? []).filter(i => i.edge_daemon_id === edgeId)
const edgeNamesOf = (i: Inbound) => (i.edge_sni?.length ? i.edge_sni : i.security.reality?.server_names ?? [i.security.acme?.domain || i.security.sni || '']).filter(Boolean)
const groups = computed(() => (nodes.value ?? []).flatMap(node => node.daemons.map(daemon => ({
  node,
  daemon: daemon as Daemon,
  inbounds: (inbounds.value ?? []).filter(i => i.daemon_id === daemon.id),
}))).filter(g => g.inbounds.length || g.daemon.enabled))

watch(() => route.query.drawer, (d) => {
  if (!d) refresh()
})

async function toggle(i: Inbound) {
  try {
    await useApi(`/inbounds/${i.id}`, { method: 'PUT', body: { ...i, enabled: !i.enabled } })
    await refresh()
  }
  catch (e) {
    useToast().error(errorMessage(e))
    await refresh()
  }
}

async function onCreated(i: Inbound) {
  picker.value = false
  await refresh()
  side.open('inbound', i.id)
}
</script>
