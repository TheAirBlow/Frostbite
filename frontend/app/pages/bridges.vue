<template>
  <div>
    <PageHeader :title="$t('Bridges')" subtitle="Relays and chains between your servers.">
      <button class="btn btn-primary btn-sm" :disabled="!(topology?.nodes.length)" @click="drawer.open('bridge')"><Icon name="fa6-solid:plus" size="13" /> {{ $t('New bridge') }}</button>
    </PageHeader>

    <Section :title="$t('Map')" hint="Dashed lines are relays, solid lines are chains, dotted lines leave your network.">
      <Skeleton v-if="!topology" :rows="1" :height="260" />
      <TopologyGraph v-else-if="topology.nodes.length" :topology="topology" />
      <EmptyState v-else icon="fa6-solid:bridge" :title="$t('Nothing to draw yet')" text="Add a couple of nodes first, then link them together here." />
    </Section>

    <div class="mt-4 grid gap-4 lg:grid-cols-2">
      <Section :title="$t('Relays')" hint="Forwarders that pass traffic to one of your inbounds.">
        <div v-if="relays.length" class="flex flex-col gap-2">
          <div v-for="e in relays" :key="e.from_inbound" class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3">
            <Icon name="fa6-solid:right-left" size="14" class="text-secondary" />
            <div class="min-w-0 flex-1"><p class="font-medium">{{ nodeName(e.from_node) }} {{ e.label }}</p><p class="text-base-content/50 text-xs">to {{ nodeName(e.to_node) }}</p></div>
            <button class="btn btn-ghost btn-xs" @click="side.open('inbound', e.from_inbound)">{{ $t('Open') }}</button>
            <ConfirmButton class="btn btn-ghost btn-xs text-error" confirm-label="Remove?" @confirmed="removeInbound(e.from_inbound!)"><Icon name="fa6-solid:trash" size="12" /></ConfirmButton>
          </div>
        </div>
        <p v-else class="text-base-content/50 text-sm">{{ $t('No relays.') }}</p>
      </Section>

      <Section :title="$t('Chains')" hint="Servers whose traffic leaves through another exit.">
        <div v-if="chains.length" class="flex flex-col gap-2">
          <div v-for="o in chains" :key="o.id" class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3">
            <Icon name="fa6-solid:link" size="14" class="text-primary" />
            <div class="min-w-0 flex-1"><p class="font-medium">{{ o.tag }}</p><p class="text-base-content/50 text-xs">{{ daemonName(o.daemon_id) }} → {{ o.target_inbound_id ? 'your inbound' : `${o.upstream?.address}:${o.upstream?.port}` }}</p></div>
            <button class="btn btn-ghost btn-xs" @click="side.open('outbound', o.id)">{{ $t('Open') }}</button>
          </div>
        </div>
        <p v-else class="text-base-content/50 text-sm">{{ $t('No chains.') }}</p>
      </Section>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { Outbound, PanelNode, Topology } from '~/types/api'

useHead({ title: 'Bridges' })
const route = useRoute()
const drawer = useDrawer()
const side = useSideDrawer()

const { data: topology, refresh } = useAsyncData('topology', () => useApi<Topology>('/topology'))
const { data: outbounds, refresh: refreshOuts } = useAsyncData('outbounds', () => useApi<Outbound[]>('/outbounds'))
const { data: nodes } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'))

const relays = computed(() => (topology.value?.edges ?? []).filter(e => e.kind === 'relay'))
const chains = computed(() => (outbounds.value ?? []).filter(o => o.kind === 'proxy'))

watch(() => [route.query.panel, route.query.drawer], ([p, d]) => {
  if (!p && !d) {
    refresh()
    refreshOuts()
  }
})

const nodeName = (id?: number) => topology.value?.nodes.find(n => n.id === id)?.name ?? '?'
const daemonName = (id: number) => nodes.value?.flatMap(n => n.daemons).find(d => d.id === id)?.name ?? '?'

const { run: removeInbound } = useAsyncAction(async (id: number) => {
  await useApi(`/inbounds/${id}`, { method: 'DELETE' })
  await refresh()
}, 'Relay removed.')
</script>
