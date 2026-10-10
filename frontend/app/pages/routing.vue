<template>
  <div>
    <PageHeader :title="$t('Routing')" subtitle="Where traffic leaves your servers, and what takes which road.">
      <select v-model="scope" class="select select-sm w-auto">
        <option value="">{{ $t('Every daemon') }}</option>
        <optgroup v-for="n in nodes ?? []" :key="n.id" :label="`${flag(n.country)} ${n.name}`">
          <option v-for="d in n.daemons" :key="d.id" :value="String(d.id)">{{ d.name }} ({{ coreLabels[d.kind] ?? d.kind }})</option>
        </optgroup>
      </select>
    </PageHeader>

    <div class="grid gap-4 xl:grid-cols-5">
      <div class="flex flex-col gap-4 xl:col-span-3">
        <Section :title="$t('Rules')" hint="The first rule that matches wins. Everything else follows the daemon's default outbound.">
          <template #actions>
            <button class="btn btn-sm btn-primary" @click="side.open('rule')"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add rule') }}</button>
          </template>
          <Skeleton v-if="!rules" :rows="3" :height="60" />
          <div v-else-if="visibleRules.length" class="flex flex-col gap-2">
            <div v-for="(r, idx) in visibleRules" :key="r.id" class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3" :class="{ 'opacity-50': !r.enabled }">
              <div class="flex flex-col">
                <button class="btn btn-ghost btn-xs btn-square" :disabled="idx === 0" :aria-label="$t('Move up')" @click="move(r, -1)"><Icon name="fa6-solid:chevron-up" size="11" /></button>
                <button class="btn btn-ghost btn-xs btn-square" :disabled="idx === visibleRules.length - 1" :aria-label="$t('Move down')" @click="move(r, 1)"><Icon name="fa6-solid:chevron-down" size="11" /></button>
              </div>
              <button class="min-w-0 flex-1 text-left" @click="side.open('rule', r.id)">
                <p class="flex flex-wrap items-center gap-2 font-medium">
                  {{ r.name || summary(r) }}
                  <span class="badge badge-sm" :class="r.outbound === 'block' ? 'badge-error badge-soft' : r.outbound === 'direct' ? 'badge-ghost' : 'badge-primary badge-soft'"><Icon name="fa6-solid:arrow-right" size="9" /> {{ r.outbound }}</span>
                  <span v-if="r.daemon_id" class="badge badge-sm badge-ghost">{{ daemonName(r.daemon_id) }}</span>
                </p>
                <p v-if="r.name" class="text-base-content/50 truncate text-xs">{{ summary(r) }}</p>
              </button>
              <input type="checkbox" class="toggle toggle-sm toggle-primary" :checked="r.enabled" :aria-label="`Enable ${r.name}`" @change="toggle(r)">
            </div>
          </div>
          <EmptyState v-else icon="fa6-solid:route" :title="$t('No rules')" text="Without rules everything goes out through the default outbound. Add one to block ads, send a country direct or push streaming through another exit." />
        </Section>

        <Section :title="$t('Quick switches')" hint="Applied to every daemon, before your own rules.">
          <form v-if="routing" class="flex flex-col" novalidate @submit.prevent="saveSwitches()">
            <ToggleRow v-model="routing.block_ads" label="Block ads and trackers" hint="Uses the geosite category-ads-all list." />
            <ToggleRow v-model="routing.block_bittorrent" label="Block BitTorrent" hint="Needs sniffing on the inbound, which the presets turn on." />
            <ToggleRow v-model="routing.block_private" label="Block private networks" hint="Stops users from reaching the node's LAN and metadata services." />
            <ToggleRow v-model="routing.block_quic" label="Block QUIC (UDP 443)" hint="Browsers fall back to TCP, which proxies handle better." />
            <FormField label="Always direct" name="direct_domains" hint="These domains skip the proxy chain on the node."><ChipInput v-model="routing.direct_domains" :placeholder="$t('example.com')" :check="checkDirectDomain" /></FormField>
            <FormBanner class="mt-3" />
            <button class="btn btn-primary btn-sm mt-3 self-end" :disabled="saving">{{ $t('Save switches') }}</button>
          </form>
        </Section>
      </div>

      <Section :title="$t('Outbounds')" hint="Exits a daemon can use. direct and block always exist." class="xl:col-span-2 self-start">
        <template #actions>
          <button class="btn btn-sm" :disabled="!allDaemons.length" @click="side.open('outbound', null, scope ? { daemon: scope } : {})"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add') }}</button>
        </template>
        <div class="flex flex-col gap-2">
          <div class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3"><Icon name="fa6-solid:globe" size="14" class="text-base-content/50" /><div class="flex-1"><p class="font-medium">{{ $t('direct') }}</p><p class="text-base-content/50 text-xs">{{ $t('Straight to the internet from the node.') }}</p></div><span class="badge badge-sm badge-ghost">{{ $t('built in') }}</span></div>
          <div class="bg-base-100 border-base-300 flex items-center gap-3 rounded-xl border p-3"><Icon name="fa6-solid:ban" size="14" class="text-base-content/50" /><div class="flex-1"><p class="font-medium">{{ $t('block') }}</p><p class="text-base-content/50 text-xs">{{ $t('Drops the connection.') }}</p></div><span class="badge badge-sm badge-ghost">{{ $t('built in') }}</span></div>
          <button v-for="o in visibleOutbounds" :key="o.id" class="bg-base-100 border-base-300 hover:border-primary/50 flex items-center gap-3 rounded-xl border p-3 text-left transition" @click="side.open('outbound', o.id)">
            <Icon :name="o.target_inbound_id ? 'fa6-solid:link' : o.kind === 'warp' ? 'fa6-solid:cloud' : 'fa6-solid:share-nodes'" size="14" class="text-primary" />
            <div class="min-w-0 flex-1">
              <p class="font-medium">{{ o.tag }}</p>
              <p class="text-base-content/50 truncate text-xs">{{ outboundText(o) }}</p>
            </div>
            <span class="badge badge-sm badge-ghost">{{ daemonName(o.daemon_id) }}</span>
          </button>
        </div>
        <p v-if="!visibleOutbounds.length" class="text-base-content/50 mt-3 text-sm">{{ $t('Add a chain to another server, a proxy from a share link, or a WARP interface.') }}</p>
      </Section>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { Inbound, Outbound, PanelNode, RoutingSettings, Rule } from '~/types/api'

useHead({ title: 'Routing' })
const route = useRoute()
const side = useSideDrawer()
const toast = useToast()
const scope = ref('')

const { data: nodes } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'))
const { data: inbounds } = useAsyncData('inbounds', () => useApi<Inbound[]>('/inbounds'))
const { data: rules, refresh: refreshRules } = useAsyncData('rules', () => useApi<Rule[]>('/rules'))
const { data: outbounds, refresh: refreshOutbounds } = useAsyncData('outbounds', () => useApi<Outbound[]>('/outbounds'))
const { data: settings } = useAsyncData('settings', () => useApi<{ routing: RoutingSettings }>('/settings'))

const routing = ref<RoutingSettings | null>(null)
watch(settings, (s) => {
  if (s && !routing.value) routing.value = { ...s.routing, direct_domains: s.routing.direct_domains ?? [] }
}, { immediate: true })

const allDaemons = computed(() => (nodes.value ?? []).flatMap(n => n.daemons))
const visibleRules = computed(() => (rules.value ?? []).filter(r => !scope.value || r.daemon_id === null || String(r.daemon_id) === scope.value))
const visibleOutbounds = computed(() => (outbounds.value ?? []).filter(o => !scope.value || String(o.daemon_id) === scope.value))

watch(() => route.query.drawer, (d) => {
  if (!d) {
    refreshRules()
    refreshOutbounds()
  }
})

function daemonName(id: number) {
  return allDaemons.value.find(d => d.id === id)?.name ?? `#${id}`
}

function outboundText(o: Outbound) {
  if (o.target_inbound_id) {
    const i = inbounds.value?.find(x => x.id === o.target_inbound_id)
    const n = nodes.value?.find(x => x.daemons.some(d => d.id === i?.daemon_id))
    return `chain to ${i?.remark || i?.tag || 'an inbound'} on ${n?.name ?? '?'}`
  }
  if (o.kind === 'warp') return `through interface ${o.interface || 'warp'}`
  if (o.kind === 'direct') return `direct${o.interface ? ` via ${o.interface}` : ''}`
  return o.upstream ? `${protocolLabels[o.upstream.protocol] ?? o.upstream.protocol} · ${o.upstream.address}:${o.upstream.port}` : o.kind
}

function summary(r: Rule): string {
  const m = r.match
  const parts: string[] = []
  const add = (label: string, v?: string[]) => v?.length && parts.push(`${label} ${v.slice(0, 3).join(', ')}${v.length > 3 ? ` +${v.length - 3}` : ''}`)
  add('domain', m.domain_suffix)
  add('exact', m.domain)
  add('keyword', m.domain_keyword)
  add('site', m.geosite)
  add('geoip', m.geoip)
  add('ip', m.ip_cidr)
  add('port', m.port)
  add('protocol', m.protocol)
  add('inbound', m.inbound_tags)
  add('user', m.users)
  if (m.network) parts.push(m.network)
  return parts.join(' · ') || 'everything'
}

async function toggle(r: Rule) {
  try {
    await useApi(`/rules/${r.id}`, { method: 'PUT', body: { daemon_id: r.daemon_id, name: r.name, match: r.match, outbound: r.outbound, enabled: !r.enabled, sort: r.sort } })
  }
  catch (e) {
    toast.error(errorMessage(e))
  }
  await refreshRules()
}

async function move(r: Rule, dir: number) {
  const ids = (rules.value ?? []).map(x => x.id)
  const i = ids.indexOf(r.id)
  const j = ids.indexOf(visibleRules.value[visibleRules.value.indexOf(r) + dir]!.id)
  ;[ids[i], ids[j]] = [ids[j]!, ids[i]!]
  try {
    await useApi('/rules/reorder', { method: 'POST', body: { ids } })
  }
  catch (e) {
    toast.error(errorMessage(e))
  }
  await refreshRules()
}

const checkDirectDomain = (v: string) => (/^[a-z0-9*.-]+\.[a-z]{2,}$/i.test(v) ? undefined : 'Enter a domain, like example.com')
const switchesForm = useForm(routing, () => ({}))

const { loading: saving, run: saveSwitches } = useAsyncAction(async () => {
  await useApi('/settings/routing', { method: 'PUT', body: { ...routing.value } })
}, 'Saved.', switchesForm)
</script>
