<template>
  <Skeleton v-if="!ready" :rows="4" />
  <form v-else class="flex flex-col gap-4" @submit.prevent="save">
    <FormField v-if="!id" label="On daemon">
      <select v-model.number="form.daemon_id" class="select w-full">
        <optgroup v-for="n in nodes" :key="n.id" :label="`${flag(n.country)} ${n.name}`">
          <option v-for="d in n.daemons" :key="d.id" :value="d.id">{{ d.name }} ({{ coreLabels[d.kind] ?? d.kind }})</option>
        </optgroup>
      </select>
    </FormField>
    <FormField label="Tag" hint="Rules and the default outbound refer to it by this name."><input v-model="form.tag" class="input w-full font-mono" :placeholder="$t('via-frankfurt')" required></FormField>

    <div class="flex flex-col gap-1">
      <p class="fieldset-legend">{{ $t('Where does it go?') }}</p>
      <Segmented v-model="mode" :options="modes" />
    </div>

    <template v-if="mode === 'chain'">
      <FormField label="Exit through" hint="Frostbite creates the credentials itself, so you never handle them.">
        <select v-model.number="form.target_inbound_id" class="select w-full" required>
          <option :value="null" disabled>{{ $t('Pick an inbound') }}</option>
          <optgroup v-for="n in nodes" :key="n.id" :label="`${flag(n.country)} ${n.name}`">
            <template v-for="d in n.daemons" :key="d.id">
              <option v-for="i in inboundsOf(d.id)" :key="i.id" :value="i.id" :disabled="d.id === form.daemon_id">{{ i.remark || i.tag }} · {{ protocolLabels[i.protocol] }}:{{ i.port }}</option>
            </template>
          </optgroup>
        </select>
      </FormField>
      <p class="text-base-content/50 text-xs">{{ $t('Make sure the inbound you chain to speaks something this daemon\'s core can dial out with.') }}</p>
    </template>

    <template v-else-if="mode === 'link'">
      <FormField label="Share link" hint="vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, anytls:// or socks://">
        <textarea v-model="form.link" class="textarea w-full font-mono text-xs" rows="3" :placeholder="$t('vless://…')" />
      </FormField>
      <div class="flex items-center gap-2">
        <button type="button" class="btn btn-sm" :class="{ 'btn-disabled': parsing || !form.link }" @click="parse"><Icon name="fa6-solid:wand-magic-sparkles" size="12" /> {{ $t('Check the link') }}</button>
        <span v-if="parsed" class="text-success text-xs"><Icon name="fa6-solid:check" size="11" /> {{ protocolLabels[parsed.protocol] ?? parsed.protocol }} · {{ parsed.address }}:{{ parsed.port }}</span>
      </div>
    </template>

    <template v-else-if="mode === 'manual' && form.upstream">
      <div class="grid gap-3 sm:grid-cols-3">
        <FormField label="Protocol"><select v-model="form.upstream.protocol" class="select w-full"><option v-for="p in ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'socks', 'http']" :key="p" :value="p">{{ protocolLabels[p] }}</option></select></FormField>
        <FormField label="Address" class="sm:col-span-1"><input v-model="form.upstream.address" class="input w-full font-mono" required></FormField>
        <FormField label="Port"><input v-model.number="form.upstream.port" type="number" class="input w-full" required></FormField>
      </div>
      <div class="grid gap-3 sm:grid-cols-2">
        <FormField v-if="['vless', 'vmess', 'tuic'].includes(form.upstream.protocol)" label="UUID"><input v-model="form.upstream.uuid" class="input w-full font-mono"></FormField>
        <FormField v-if="['socks', 'http'].includes(form.upstream.protocol)" label="Username"><input v-model="form.upstream.username" class="input w-full"></FormField>
        <FormField v-if="!['vless', 'vmess'].includes(form.upstream.protocol)" label="Password"><input v-model="form.upstream.password" class="input w-full font-mono"></FormField>
      </div>
      <SchemaForm v-model="upTransport" :fields="schema?.transport ?? []" :context="{ protocol: form.upstream.protocol }" />
      <div class="divider my-0">{{ $t('Security') }}</div>
      <SchemaForm v-model="upSecurity" :fields="clientSecurity" :context="{ protocol: form.upstream.protocol }" />
      <SchemaForm v-model="upOptions" :fields="optionFields" :context="{ protocol: form.upstream.protocol }" />
    </template>

    <template v-else-if="mode === 'warp'">
      <WarpAccount />
      <Advanced :title="$t('Use a network interface instead')">
        <FormField label="Network interface" hint="If the node already runs its own WARP interface, name it here and the panel account is ignored.">
          <input v-model="form.interface" class="input w-full font-mono" :placeholder="$t('warp')">
        </FormField>
      </Advanced>
    </template>

    <template v-else-if="mode === 'direct'">
      <FormField label="Network interface" hint="Leave empty to use the default route.">
        <input v-model="form.interface" class="input w-full font-mono" :placeholder="$t('eth1')">
      </FormField>
    </template>

    <Advanced>
      <FormField label="Resolver strategy" hint="Applies to direct style outbounds."><select v-model="form.strategy" class="select w-full"><option value="">{{ $t('Daemon default') }}</option><option v-for="s in ['prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only']" :key="s">{{ s }}</option></select></FormField>
    </Advanced>

    <div class="bg-base-100 border-base-300 sticky bottom-0 -mx-4 -mb-4 flex items-center justify-between gap-2 border-t p-3">
      <ConfirmButton v-if="id" type="button" class="btn btn-ghost text-error" confirm-label="Delete?" @confirmed="remove"><Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}</ConfirmButton>
      <span v-else />
      <button class="btn btn-primary" :class="{ 'btn-disabled': saving }"><span v-if="saving" class="loading loading-spinner loading-xs" /> {{ id ? 'Save changes' : 'Add outbound' }}</button>
    </div>
  </form>
</template>

<script setup lang="ts">
import type { Inbound, Outbound, PanelNode, Schema, SchemaField, Upstream } from '~/types/api'

const props = defineProps<{ id: number | null }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string }], done: [] }>()
const route = useRoute()

const nodes = ref<PanelNode[]>([])
const inbounds = ref<Inbound[]>([])
const schema = ref<Schema | null>(null)
const ready = ref(false)
const mode = ref('chain')
const parsed = ref<Upstream | null>(null)

const form = reactive({
  daemon_id: 0, tag: '', kind: 'proxy', link: '', target_inbound_id: null as number | null, interface: '', strategy: '', sort: 0,
  upstream: null as Upstream | null,
})

const modes = [
  { value: 'chain', label: 'Chain', icon: 'fa6-solid:link' },
  { value: 'link', label: 'Share link', icon: 'fa6-solid:paste' },
  { value: 'manual', label: 'Manual', icon: 'fa6-solid:pen-ruler' },
  { value: 'warp', label: 'WARP', icon: 'fa6-solid:cloud' },
  { value: 'direct', label: 'Interface', icon: 'fa6-solid:ethernet' },
]

const blankUpstream = (): Upstream => ({ name: '', protocol: 'vless', address: '', port: 443, uuid: '', password: '', username: '', transport: { type: 'tcp' }, security: { type: 'tls' }, options: {} })
const upTransport = computed({ get: () => form.upstream!.transport as unknown as Record<string, unknown>, set: v => (form.upstream!.transport = v as unknown as Upstream['transport']) })
const upSecurity = computed({ get: () => form.upstream!.security as unknown as Record<string, unknown>, set: v => (form.upstream!.security = v as unknown as Upstream['security']) })
const upOptions = computed({ get: () => form.upstream!.options as Record<string, unknown>, set: v => (form.upstream!.options = v) })
const clientSecurity = computed<SchemaField[]>(() => (schema.value?.security ?? []).filter(f => !['cert_path', 'key_path', 'ech_key'].includes(f.path) && !f.path.startsWith('reality.private')))
const optionFields = computed<SchemaField[]>(() => (schema.value?.options ?? []).filter(f => !f.path.startsWith('mux') && !f.path.startsWith('fragment') && f.show?.protocol?.includes(form.upstream?.protocol ?? '')))

const inboundsOf = (daemonId: number) => inbounds.value.filter(i => i.daemon_id === daemonId && i.protocol !== 'forward')

onMounted(async () => {
  const [ns, ins, sc, outs] = await Promise.all([useApi<PanelNode[]>('/nodes'), useApi<Inbound[]>('/inbounds'), useApi<Schema>('/schema'), useApi<Outbound[]>('/outbounds')])
  nodes.value = ns
  inbounds.value = ins
  schema.value = sc

  if (props.id) {
    const o = outs.find(x => x.id === props.id)
    if (!o) return
    Object.assign(form, { daemon_id: o.daemon_id, tag: o.tag, kind: o.kind, target_inbound_id: o.target_inbound_id, interface: o.interface, strategy: o.strategy, sort: o.sort, upstream: o.upstream })
    mode.value = o.target_inbound_id ? 'chain' : o.kind === 'warp' ? 'warp' : o.kind === 'direct' ? 'direct' : 'manual'
    if (mode.value === 'manual' && !form.upstream) form.upstream = blankUpstream()
    emit('title', { title: o.tag, subtitle: 'Outbound' })
  }
  else {
    form.daemon_id = Number(route.query.daemon) || ns.flatMap(n => n.daemons)[0]?.id || 0
    emit('title', { title: 'New outbound', subtitle: 'An exit for traffic' })
  }
  ready.value = true
})

watch(mode, (m) => {
  if (m === 'manual' && !form.upstream) form.upstream = blankUpstream()
  parsed.value = null
})

const { loading: parsing, run: parse } = useAsyncAction(async () => {
  parsed.value = await useApi<Upstream>('/tools/parse-link', { method: 'POST', body: { link: form.link } })
})

function body() {
  const kind = mode.value === 'warp' ? 'warp' : mode.value === 'direct' ? 'direct' : 'proxy'
  return {
    daemon_id: form.daemon_id, tag: form.tag.trim(), kind, interface: form.interface, strategy: form.strategy, sort: form.sort,
    target_inbound_id: mode.value === 'chain' ? form.target_inbound_id : null,
    link: mode.value === 'link' ? form.link : '',
    upstream: mode.value === 'manual' ? form.upstream : null,
  }
}

const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi(props.id ? `/outbounds/${props.id}` : '/outbounds', { method: props.id ? 'PUT' : 'POST', body: body() })
  emit('done')
}, 'Saved.')

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/outbounds/${props.id}`, { method: 'DELETE' })
  emit('done')
}, 'Outbound deleted.')
</script>
