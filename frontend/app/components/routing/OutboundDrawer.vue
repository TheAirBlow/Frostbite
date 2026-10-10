<template>
  <Skeleton v-if="!ready" :rows="4" />
  <form v-else class="flex flex-col gap-4" novalidate @submit.prevent="save()">
    <FormField v-if="!id" label="On daemon" name="daemon_id">
      <select v-model.number="form.daemon_id" class="select w-full">
        <optgroup v-for="n in nodes" :key="n.id" :label="`${flag(n.country)} ${n.name}`">
          <option v-for="d in n.daemons" :key="d.id" :value="d.id">{{ d.name }} ({{ coreLabels[d.kind] ?? d.kind }})</option>
        </optgroup>
      </select>
    </FormField>
    <FormField label="Tag" name="tag" hint="Rules and the default outbound refer to it by this name." required><input v-model="form.tag" class="input w-full font-mono" :placeholder="$t('via-frankfurt')" autocomplete="off"></FormField>

    <div class="flex flex-col gap-1">
      <p class="fieldset-legend">{{ $t('Where does it go?') }}</p>
      <Segmented v-model="mode" :options="modes" />
    </div>

    <template v-if="mode === 'chain'">
      <FormField label="Exit through" name="target_inbound_id" hint="Frostbite creates the credentials itself, so you never handle them." required>
        <select v-model.number="form.target_inbound_id" class="select w-full">
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
      <FormField label="Share link" name="link" required hint="vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, anytls:// or socks://">
        <textarea v-model="form.link" class="textarea w-full font-mono text-xs" rows="3" :placeholder="$t('vless://…')" />
      </FormField>
      <div class="flex items-center gap-2">
        <button type="button" class="btn btn-sm" :disabled="parsing || !form.link" @click="parse"><Icon name="fa6-solid:wand-magic-sparkles" size="12" /> {{ $t('Check the link') }}</button>
        <span v-if="parsed" class="text-success text-xs"><Icon name="fa6-solid:check" size="11" /> {{ protocolLabels[parsed.protocol] ?? parsed.protocol }} · {{ parsed.address }}:{{ parsed.port }}</span>
      </div>
    </template>

    <template v-else-if="mode === 'manual' && form.upstream">
      <div class="grid gap-3 sm:grid-cols-3">
        <FormField label="Protocol" name="upstream.protocol"><select v-model="form.upstream.protocol" class="select w-full"><option v-for="p in ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'socks', 'http']" :key="p" :value="p">{{ protocolLabels[p] }}</option></select></FormField>
        <FormField label="Address" name="upstream.address" class="sm:col-span-1" required><input v-model="form.upstream.address" class="input w-full font-mono" autocomplete="off"></FormField>
        <FormField label="Port" name="upstream.port" required><input v-model.number="form.upstream.port" type="number" min="1" max="65535" class="input w-full"></FormField>
      </div>
      <div class="grid gap-3 sm:grid-cols-2">
        <FormField v-if="['vless', 'vmess', 'tuic'].includes(form.upstream.protocol)" label="UUID" name="upstream.uuid" required><input v-model="form.upstream.uuid" class="input w-full font-mono"></FormField>
        <FormField v-if="['socks', 'http'].includes(form.upstream.protocol)" label="Username" name="upstream.username"><input v-model="form.upstream.username" class="input w-full"></FormField>
        <FormField v-if="!['vless', 'vmess'].includes(form.upstream.protocol)" label="Password" name="upstream.password" :required="!['socks', 'http'].includes(form.upstream.protocol)"><input v-model="form.upstream.password" class="input w-full font-mono"></FormField>
      </div>
      <SchemaForm v-model="upTransport" :fields="schema?.transport ?? []" prefix="upstream.transport." :context="{ protocol: form.upstream.protocol }" />
      <div class="divider my-0">{{ $t('Security') }}</div>
      <SchemaForm v-model="upSecurity" :fields="clientSecurity" prefix="upstream.security." :context="{ protocol: form.upstream.protocol }" />
      <SchemaForm v-model="upOptions" :fields="optionFields" prefix="upstream.options." :context="{ protocol: form.upstream.protocol }" />
    </template>

    <template v-else-if="mode === 'warp'">
      <WarpAccount />
      <Advanced :title="$t('Use a network interface instead')">
        <FormField label="Network interface" name="interface" hint="If the node already runs its own WARP interface, name it here and the panel account is ignored.">
          <input v-model="form.interface" class="input w-full font-mono" :placeholder="$t('warp')">
        </FormField>
      </Advanced>
    </template>

    <template v-else-if="mode === 'direct'">
      <FormField label="Network interface" name="interface" hint="Leave empty to use the default route.">
        <input v-model="form.interface" class="input w-full font-mono" :placeholder="$t('eth1')">
      </FormField>
    </template>

    <Advanced>
      <FormField label="Resolver strategy" name="strategy" hint="Applies to direct style outbounds."><select v-model="form.strategy" class="select w-full"><option value="">{{ $t('Daemon default') }}</option><option v-for="s in ['prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only']" :key="s">{{ s }}</option></select></FormField>
    </Advanced>

    <FormFooter>
      <ConfirmButton v-if="id" type="button" class="btn btn-ghost text-error" confirm-label="Delete?" @confirmed="remove"><Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}</ConfirmButton>
      <span v-else />
      <button class="btn btn-primary" :disabled="saving"><span v-if="saving" class="loading loading-spinner loading-xs" /> {{ id ? 'Save changes' : 'Add outbound' }}</button>
    </FormFooter>
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

const formApi = useForm(() => (ready.value ? form : null), (f) => {
  const e: Record<string, Check> = {
    tag: checkRequired(f.tag, 'Give the outbound a tag') ?? (/\s/.test(f.tag) ? 'A tag can\'t contain spaces' : ['direct', 'block'].includes(f.tag) ? '"direct" and "block" are built in, pick another tag' : undefined),
  }
  if (mode.value === 'chain') e.target_inbound_id = f.target_inbound_id ? undefined : 'Pick the inbound to exit through'
  if (mode.value === 'link') e.link = checkRequired(f.link, 'Paste a share link') ?? (/^[a-z0-9+.-]+:\/\/\S+$/i.test(f.link.trim()) ? undefined : 'That does not look like a share link, such as vless://…')
  if (mode.value === 'manual' && f.upstream) {
    const u = f.upstream
    e['upstream.address'] = checkRequired(u.address, 'Enter the server address') ?? checkHost(u.address)
    e['upstream.port'] = checkPort(u.port)
    if (['vless', 'vmess', 'tuic'].includes(u.protocol)) e['upstream.uuid'] = checkRequired(u.uuid, 'A UUID is required') ?? (/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(u.uuid ?? '') ? undefined : 'That is not a UUID')
    else if (!['socks', 'http'].includes(u.protocol)) e['upstream.password'] = checkRequired(u.password, 'A password is required')
  }
  return problems(e)
})

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

// a link that does not parse is a mistake in the link field, not a toast
const { loading: parsing, run: parse } = useAsyncAction(async () => {
  try {
    parsed.value = await useApi<Upstream>('/tools/parse-link', { method: 'POST', body: { link: form.link } })
  }
  catch (e) {
    parsed.value = null
    formApi.setError('link', errorMessage(e))
  }
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
}, 'Saved.', formApi)

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/outbounds/${props.id}`, { method: 'DELETE' })
  emit('done')
}, 'Outbound deleted.')
</script>
