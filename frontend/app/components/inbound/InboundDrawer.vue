<template>
  <Skeleton v-if="!form" :rows="5" :height="60" />
  <div v-else class="flex flex-col gap-4">
    <Tabs v-model="tab" :tabs="tabs" />

    <form id="inbound-form" class="flex flex-col gap-4" novalidate @submit.prevent="save()">
      <template v-if="tab === 'general'">
        <div class="grid gap-3 sm:grid-cols-2">
          <FormField label="Name" name="remark" hint="What you see in the panel."><input v-model="form.remark" class="input w-full" :placeholder="$t('Reality, main')"></FormField>
          <FormField label="Tag" name="tag" hint="Unique on its daemon. Routing rules refer to it." required><input v-model="form.tag" class="input w-full font-mono" autocomplete="off"></FormField>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <FormField label="Protocol" name="protocol">
            <select v-model="form.protocol" class="select w-full" :disabled="!!id" @change="onProtocolChange">
              <option v-for="p in caps?.protocols ?? []" :key="p" :value="p">{{ protocolLabels[p] ?? p }}</option>
            </select>
          </FormField>
          <FormField label="Port" name="port" :hint="udp ? 'This one uses UDP.' : ''" required><input v-model.number="form.port" type="number" min="1" max="65535" class="input w-full"></FormField>
        </div>
        <FormField v-if="edgeChoices.length && form.protocol !== 'forward'" label="Shared port" name="edge_daemon_id" hint="Behind an edge daemon this inbound shares its port with others and is picked by the TLS server name. Needs tls or reality, over TCP.">
          <select v-model="form.edge_daemon_id" class="select w-full">
            <option :value="null">{{ $t('Its own port, listening directly') }}</option>
            <option v-for="e in edgeChoices" :key="e.id" :value="e.id">Behind {{ e.name }} ({{ e.edge_listen.join(', ') }})</option>
          </select>
        </FormField>
        <FormField v-if="form.edge_daemon_id" label="Server names" name="edge_sni" hint="Empty uses the REALITY server names or the TLS domain. Wildcards like *.example.com work.">
          <ChipInput v-model="form.edge_sni" :placeholder="$t('vpn.example.com')" :check="checkServerName" />
        </FormField>
        <p v-if="form.edge_daemon_id && daemon?.kind === 'singbox'" class="text-warning -mt-1 text-xs">{{ $t('sing-box does not read the PROXY header, so users of this inbound will all appear to connect from 127.0.0.1. IP limits and the connected-from list will not be accurate for it.') }}</p>
        <ToggleRow v-model="form.enabled" label="Enabled" hint="A disabled inbound stops listening and leaves subscriptions." />
        <Advanced>
          <div class="grid gap-3 sm:grid-cols-2">
            <FormField label="Listen address" name="listen" hint="Empty listens on every address."><input v-model="form.listen" class="input w-full font-mono" placeholder="0.0.0.0" autocomplete="off"></FormField>
            <FormField label="Sort order" name="sort" hint="Lower comes first."><input v-model.number="form.sort" type="number" class="input w-full"></FormField>
          </div>
        </Advanced>

        <template v-if="form.protocol === 'forward'">
          <div class="divider my-0">{{ $t('Relay target') }}</div>
          <div class="grid gap-3 sm:grid-cols-3">
            <FormField label="Address" name="forward.address" required><input v-model="forward.address" class="input w-full font-mono" autocomplete="off"></FormField>
            <FormField label="Port" name="forward.port" required><input v-model.number="forward.port" type="number" min="1" max="65535" class="input w-full"></FormField>
            <FormField label="Network" name="forward.network"><select v-model="forward.network" class="select w-full"><option value="tcp">{{ $t('tcp') }}</option><option value="udp">{{ $t('udp') }}</option><option value="tcp,udp">{{ $t('tcp,udp') }}</option></select></FormField>
          </div>
          <p class="text-base-content/50 text-xs">{{ $t('Relays made with the bridge wizard keep this in sync with their target automatically.') }}</p>
        </template>
      </template>

      <template v-else-if="tab === 'transport'">
        <template v-if="form.protocol !== 'forward'">
          <SchemaForm v-model="transportModel" :fields="transportFields" prefix="transport." :context="{ protocol: form.protocol }" />
          <p v-if="!transportFields.length" class="text-base-content/50 text-sm">{{ $t('This protocol has its own transport.') }}</p>
          <div v-if="!['mtproto', 'turnable'].includes(form.protocol)" class="divider my-0">{{ $t('Security') }}</div>
          <SchemaForm v-if="!['mtproto', 'turnable'].includes(form.protocol)" v-model="securityModel" :fields="securityFields" prefix="security." :context="{ protocol: form.protocol }" />

          <section v-if="form.security.type === 'tls'" class="surface flex flex-col gap-3 p-4">
            <ToggleRow :model-value="!!form.security.acme" label="Get the certificate automatically" hint="The daemon requests and renews a free Let's Encrypt certificate for the domain. The domain must point at this node and port 80 must be free there." @update:model-value="setAcme" />
            <template v-if="form.security.acme">
              <div class="grid gap-3 sm:grid-cols-2">
                <FormField label="Domain" name="security.acme.domain" required><input v-model="acme!.domain" class="input w-full font-mono" :placeholder="$t('vpn.example.com')" autocomplete="off"></FormField>
                <FormField label="Email" name="security.acme.email" hint="Optional. Let's Encrypt writes here before a certificate expires."><input v-model="acme!.email" type="email" class="input w-full"></FormField>
              </div>
              <p v-for="c in certStates" :key="c.domain" class="flex items-center gap-2 text-sm" :class="c.ok ? 'text-success' : c.placeholder ? 'text-warning' : 'text-base-content/60'">
                <Icon :name="c.ok ? 'fa6-solid:circle-check' : 'fa6-solid:hourglass-half'" size="13" />
                <template v-if="c.ok">Certificate valid until {{ formatDate(c.expires) }}.</template>
                <template v-else-if="c.placeholder">Serving a self signed stand-in{{ c.error ? `. Last attempt: ${c.error}` : '. Requesting the real one…' }}</template>
                <template v-else>{{ c.error || 'Waiting for the daemon.' }}</template>
              </p>
            </template>
          </section>

          <section v-if="form.security.type === 'reality' && reality" class="surface flex flex-col gap-3 p-4">
            <h4 class="text-base-content/70 text-sm font-semibold tracking-wide uppercase">REALITY</h4>
            <FormField label="Handshake target" name="security.reality.dest" hint="A real site with TLS 1.3 and h2. Your server will pretend to be it." required>
              <div class="join w-full">
                <input v-model="reality.dest" class="input join-item w-full font-mono" :placeholder="$t('www.cloudflare.com:443')" autocomplete="off">
                <button type="button" class="btn join-item" :disabled="testing" @click="testDest"><span v-if="testing" class="loading loading-spinner loading-xs" /><Icon v-else name="fa6-solid:vial" size="12" /> {{ $t('Test') }}</button>
              </div>
              <p v-if="testResult" class="mt-1 text-xs" :class="testResult.ok ? 'text-success' : 'text-error'">{{ testResult.ok ? testResult.output : testResult.error }}</p>
            </FormField>
            <FormField label="Server names (SNI)" name="security.reality.server_names" hint="Clients send one of these. Usually the target's domain." required><ChipInput v-model="reality.server_names" :placeholder="$t('www.cloudflare.com')" :check="checkServerName" /></FormField>
            <FormField label="Short IDs" name="security.reality.short_ids" hint="Up to 16 hex characters each, an even number of them. Clients carry one of them.">
              <div class="flex items-center gap-2"><div class="min-w-0 flex-1"><ChipInput v-model="reality.short_ids" :check="checkShortId" /></div><button type="button" class="btn btn-sm" @click="newShortId"><Icon name="fa6-solid:plus" size="11" /> {{ $t('New') }}</button></div>
            </FormField>
            <div class="grid gap-3 sm:grid-cols-2">
              <FormField label="Public key" name="security.reality.public_key"><input v-model="reality.public_key" class="input w-full font-mono text-xs" readonly></FormField>
              <FormField label="Private key" name="security.reality.private_key" required><input v-model="reality.private_key" class="input w-full font-mono text-xs" type="password" autocomplete="off"></FormField>
            </div>
            <ConfirmButton type="button" class="btn btn-sm self-start" confirm-label="Clients must update their link" @confirmed="newKeys"><Icon name="fa6-solid:key" size="12" /> {{ $t('Generate new key pair') }}</ConfirmButton>
            <FormField label="PROXY header to the target" name="security.reality.xver" hint="Lets the target see the real client address. The target has to expect it. For nginx that means proxy_protocol on its listener.">
              <select class="select w-full" :value="reality.xver ?? 0" @change="reality.xver = Number(($event.target as HTMLSelectElement).value)">
                <option :value="0">{{ $t('Off') }}</option>
                <option :value="1">{{ $t('Version 1') }}</option>
                <option :value="2">{{ $t('Version 2') }}</option>
              </select>
              <p v-if="reality.xver && daemon?.kind === 'singbox'" class="text-warning mt-1 text-xs">{{ $t('sing-box cannot send a PROXY header, so this does nothing there.') }}</p>
            </FormField>
            <FormField label="Spider X" name="security.reality.spider_x" hint="The path REALITY crawls on the target. Rarely needs changing."><input v-model="reality.spider_x" class="input w-full font-mono" placeholder="/"></FormField>
          </section>
        </template>
        <p v-else class="text-base-content/50 text-sm">{{ $t('A relay passes bytes through untouched, so there is nothing to configure here.') }}</p>
      </template>

      <template v-else-if="tab === 'protocol'">
        <TurnableRoutes v-if="form.protocol === 'turnable'" v-model="turnableRoutes" />
        <SchemaForm v-model="optionsModel" :fields="optionFields" prefix="options." :context="{ protocol: form.protocol }" />
        <p v-if="!optionFields.length && form.protocol !== 'turnable'" class="text-base-content/50 text-sm">{{ $t('This protocol has no extra settings.') }}</p>

        <ConfirmButton v-if="['turnable', 'wireguard'].includes(form.protocol)" type="button" class="btn btn-sm self-start" confirm-label="Clients must update their link" @confirmed="newServerKeys">
          <Icon name="fa6-solid:key" size="12" /> {{ $t('Generate new key pair') }}
        </ConfirmButton>

        <template v-if="form.protocol === 'shadowsocks' && String(form.options.method ?? '').startsWith('2022-')">
          <button type="button" class="btn btn-sm self-start" @click="newSsKey"><Icon name="fa6-solid:key" size="12" /> {{ $t('New server key') }}</button>
        </template>

        <template v-if="!['forward', 'mtproto', 'turnable'].includes(form.protocol)">
          <div class="divider my-0">{{ $t('Sniffing') }}</div>
          <SchemaForm v-model="sniffingModel" :fields="schema?.sniffing ?? []" prefix="sniffing." />

          <div class="divider my-0">{{ $t('What clients get') }}</div>
          <p class="text-base-content/50 -mt-2 text-xs">{{ $t('These travel in subscriptions. The server itself does not enforce them.') }}</p>
          <ToggleRow :model-value="!!mux?.enabled" label="Multiplexing" hint="Many streams over one connection." @update:model-value="setMux({ enabled: $event })" />
          <div v-if="mux?.enabled" class="grid gap-3 sm:grid-cols-3">
            <FormField label="Protocol" name="options.mux.protocol"><select class="select w-full" :value="mux.protocol || 'h2mux'" @change="setMux({ protocol: ($event.target as HTMLSelectElement).value })"><option value="h2mux">{{ $t('h2mux') }}</option><option value="smux">{{ $t('smux') }}</option><option value="yamux">{{ $t('yamux') }}</option></select></FormField>
            <FormField label="Concurrency" name="options.mux.concurrency"><input type="number" min="0" class="input w-full" :value="mux.concurrency || ''" @input="setMux({ concurrency: Number(($event.target as HTMLInputElement).value) })"></FormField>
            <ToggleRow :model-value="!!mux.padding" label="Padding" @update:model-value="setMux({ padding: $event })" />
          </div>
        </template>
      </template>

      <template v-else-if="tab === 'advanced'">
        <FormField label="Raw patch" name="raw_patch" hint="A JSON object merged over this inbound's generated config. null removes a key.">
          <JsonField v-model="form.raw_patch" :rows="10" placeholder='{ "sniffing": { "metadataOnly": true } }' />
        </FormField>
        <div v-if="id" class="flex flex-col gap-1">
          <p class="fieldset-legend">{{ $t('Final config') }}</p>
          <p class="text-base-content/60 text-xs">{{ $t('See the whole generated config of this daemon, with your patch applied.') }}</p>
          <button type="button" class="btn btn-sm self-start" @click="showConfig = true"><Icon name="fa6-solid:code" size="12" /> {{ $t('Show config') }}</button>
        </div>
      </template>
    </form>

    <HostEditor v-if="tab === 'hosts' && id" :inbound-id="id" :inbound="inbound!" :node-address="nodeAddress" @changed="reload" />
    <InboundAccess v-else-if="tab === 'access' && id" :inbound-id="id" />
    <EmptyState v-else-if="(tab === 'hosts' || tab === 'access') && !id" icon="fa6-solid:floppy-disk" :title="$t('Save it first')" text="Hosts and access can be set once the inbound exists." />

    <FormFooter v-if="['general', 'transport', 'protocol', 'advanced'].includes(tab)">
      <ConfirmButton v-if="id" type="button" class="btn btn-ghost text-error" confirm-label="Delete inbound?" @confirmed="remove"><Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}</ConfirmButton>
      <span v-else />
      <button form="inbound-form" class="btn btn-primary" :disabled="saving"><span v-if="saving" class="loading loading-spinner loading-xs" /> {{ id ? 'Save changes' : 'Create inbound' }}</button>
    </FormFooter>

    <ConfigPreview v-if="showConfig && daemon" :daemon="daemon" @close="showConfig = false" />
  </div>
</template>

<script setup lang="ts">
import type { CommandResult, CoreInfo, Daemon, Inbound, Mux, PanelNode, Reality, Schema, SchemaField, TurnableRoute } from '~/types/api'

const props = defineProps<{ id: number | null }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string, width?: string }], done: [] }>()
const route = useRoute()

const tab = ref('general')
const tabs = computed(() => [
  { id: 'general', label: 'General', icon: 'fa6-solid:gear' },
  { id: 'transport', label: 'Transport', icon: 'fa6-solid:shield-halved' },
  { id: 'protocol', label: 'Protocol', icon: 'fa6-solid:sliders' },
  { id: 'hosts', label: 'Hosts', icon: 'fa6-solid:globe' },
  { id: 'access', label: 'Access', icon: 'fa6-solid:layer-group' },
  { id: 'advanced', label: 'Advanced', icon: 'fa6-solid:code' },
])

interface Form {
  daemon_id: number
  tag: string
  remark: string
  protocol: string
  listen: string
  port: number
  enabled: boolean
  sort: number
  transport: Record<string, unknown>
  security: Record<string, unknown>
  options: Record<string, unknown>
  sniffing: Record<string, unknown>
  forward: Record<string, unknown> | null
  raw_patch: Record<string, unknown> | null
  edge_daemon_id: number | null
  edge_sni: string[]
}

const form = ref<Form | null>(null)
const inbound = ref<Inbound | null>(null)
const schema = ref<Schema | null>(null)
const cores = ref<CoreInfo[]>([])
const nodes = ref<PanelNode[]>([])
const showConfig = ref(false)

const daemon = computed<Daemon | null>(() => nodes.value.flatMap(n => n.daemons).find(d => d.id === form.value?.daemon_id) ?? null)
const node = computed(() => nodes.value.find(n => n.daemons.some(d => d.id === form.value?.daemon_id)))
const nodeAddress = computed(() => node.value?.address ?? '')
const caps = computed(() => cores.value.find(c => c.kind === daemon.value?.kind)?.caps)
const edgeChoices = computed(() => (node.value?.daemons ?? []).filter(d => d.kind === 'edge' && d.enabled))
const udp = computed(() => ['hysteria2', 'tuic'].includes(form.value?.protocol ?? '') || form.value?.transport.type === 'kcp')

async function load() {
  const [sc, cs, ns] = await Promise.all([useApi<Schema>('/schema'), useApi<CoreInfo[]>('/cores'), useApi<PanelNode[]>('/nodes')])
  schema.value = sc
  cores.value = cs
  nodes.value = ns

  if (props.id) {
    const list = await useApi<Inbound[]>('/inbounds')
    const i = list.find(x => x.id === props.id)
    if (!i) return
    inbound.value = i
    form.value = formOf(i)
    migrateTurnable(form.value)
    emit('title', { title: i.remark || i.tag, subtitle: `${protocolLabels[i.protocol] ?? i.protocol} on :${i.port}`, width: 'max-w-2xl' })
    return
  }

  const daemonId = Number(route.query.daemon)
  const d = ns.flatMap(n => n.daemons).find(x => x.id === daemonId) ?? ns.flatMap(n => n.daemons)[0]
  form.value = {
    daemon_id: d?.id ?? 0, tag: '', remark: '', protocol: cs.find(c => c.kind === d?.kind)?.caps.protocols[0] ?? 'vless', listen: '', port: 443,
    enabled: true, sort: 0, transport: { type: 'tcp' }, security: { type: 'none' }, options: {}, sniffing: { enabled: true, route_only: false, dest_override: false },
    forward: null, raw_patch: null, edge_daemon_id: null, edge_sni: [],
  }
  emit('title', { title: 'New inbound', subtitle: `on ${d?.name ?? ''}`, width: 'max-w-2xl' })
}

onMounted(load)

// a plain deep copy, so editing never touches the loaded record
function clone<T extends object>(v: T): Record<string, unknown> {
  return structuredClone(toRaw(v)) as unknown as Record<string, unknown>
}

function formOf(i: Inbound): Form {
  return {
    daemon_id: i.daemon_id, tag: i.tag, remark: i.remark, protocol: i.protocol, listen: i.listen, port: i.port, enabled: i.enabled, sort: i.sort,
    transport: clone(i.transport), security: clone(i.security),
    options: clone(i.options), sniffing: clone(i.sniffing),
    forward: i.forward ? { ...i.forward } : null, raw_patch: i.raw_patch ? clone(i.raw_patch) : null,
    edge_daemon_id: i.edge_daemon_id, edge_sni: [...(i.edge_sni ?? [])],
  }
}

async function reload() {
  await load()
  await refreshNuxtData('inbounds')
}

// the forms edit sub objects through v-model, so give them writable views onto the form
const transportModel = computed({ get: () => form.value!.transport, set: v => (form.value!.transport = v) })
const securityModel = computed({ get: () => form.value!.security, set: v => (form.value!.security = v) })
const optionsModel = computed({ get: () => form.value!.options, set: v => (form.value!.options = v) })
const sniffingModel = computed({ get: () => form.value!.sniffing, set: v => (form.value!.sniffing = v) })

// only offer what the core can run
function limited(fields: SchemaField[] | undefined, allowed: string[] | undefined): SchemaField[] {
  return (fields ?? []).map(f => (f.path === 'type' && f.options && allowed ? { ...f, options: f.options.filter(o => allowed.includes(o)) } : f))
}

const transportFields = computed(() => (['hysteria2', 'tuic', 'anytls', 'naive', 'shadowsocks', 'socks', 'http', 'mixed', 'mtproto', 'turnable'].includes(form.value?.protocol ?? '')
  ? []
  : limited(schema.value?.transport, caps.value?.transports)))
const securityFields = computed(() => {
  const fixedTLS = ['hysteria2', 'tuic', 'anytls', 'naive'].includes(form.value?.protocol ?? '')
  const fields = limited(schema.value?.security, caps.value?.securities).filter(f => !f.path.startsWith('reality'))
  return fixedTLS ? fields.filter(f => f.path !== 'type') : fields
})
const optionFields = computed(() => (schema.value?.options ?? []).filter((f) => {
  if (f.path.startsWith('mux') || f.path.startsWith('fragment')) return false
  const need = f.show?.protocol
  return !need || need.includes(form.value?.protocol ?? '')
}))

watch(() => form.value?.protocol, (p) => {
  // TLS only protocols need tls from the start
  if (form.value && ['hysteria2', 'tuic', 'anytls', 'naive'].includes(p ?? '') && form.value.security.type !== 'tls') form.value.security = { type: 'tls', cert_path: '/certs/fullchain.pem', key_path: '/certs/privkey.pem' }
})

// an inbound saved before destinations became a list carries one flat destination, which becomes the first entry
function migrateTurnable(f: Form) {
  const o = f.options
  if (f.protocol !== 'turnable' || (o.t_routes as unknown[] | undefined)?.length || (!o.t_target && !o.t_socket)) return
  o.t_routes = [{ id: 'main', name: '', target: String(o.t_target ?? ''), socket: String(o.t_socket || 'udp'), transport: String(o.t_transport || 'mpath'), encryption: String(o.t_encryption || 'handshake') }]
  const { t_target: _a, t_socket: _b, t_transport: _c, t_encryption: _d, ...rest } = o
  f.options = rest
}

// what a freshly picked protocol needs before it can run: keys, a subnet, a first destination
async function onProtocolChange() {
  const f = form.value
  if (!f) return
  f.options = {}
  f.forward = f.protocol === 'forward' ? { address: '', port: 0, network: 'tcp' } : null
  try {
    if (f.protocol === 'turnable') {
      const k = await useApi<{ private: string, public: string }>('/tools/keys', { method: 'POST', body: { type: 'turnable' } })
      f.options = { t_call_id: '', t_private: k.private, t_public: k.public, t_routes: [{ id: 'main', name: '', target: '127.0.0.1:51820', socket: 'udp', transport: 'mpath', encryption: 'handshake' }] }
      f.port = 56000
    }
    else if (f.protocol === 'wireguard') {
      const k = await useApi<{ private: string, public: string }>('/tools/keys', { method: 'POST', body: { type: 'wireguard' } })
      f.options = { wg_subnet: '10.8.0.0/16', wg_private: k.private, wg_public: k.public }
    }
  }
  catch (e) {
    useToast().error(errorMessage(e))
  }
}

// the destinations of a Turnable tunnel, as the editor sees them
const turnableRoutes = computed<TurnableRoute[]>({
  get: () => ((form.value?.options.t_routes as TurnableRoute[] | undefined) ?? []),
  set: v => (form.value!.options = { ...form.value!.options, t_routes: v }),
})

async function newServerKeys() {
  const f = form.value!
  const type = f.protocol === 'wireguard' ? 'wireguard' : 'turnable'
  const k = await useApi<{ private: string, public: string }>('/tools/keys', { method: 'POST', body: { type } })
  f.options = f.protocol === 'wireguard'
    ? { ...f.options, wg_private: k.private, wg_public: k.public }
    : { ...f.options, t_private: k.private, t_public: k.public }
}

const checkServerName = (v: string) => (/^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(v) ? undefined : 'Not a valid server name')
const checkShortId = (v: string) => (/^([0-9a-f]{2}){0,8}$/i.test(v) ? undefined : 'Use up to 16 hex characters, an even number')

const forward = computed(() => form.value!.forward ?? ({ address: '', port: 0, network: 'tcp' } as Record<string, unknown>))

const reality = computed<Reality | null>(() => {
  const s = form.value?.security
  if (!s || s.type !== 'reality') return null
  if (!s.reality) s.reality = { dest: '', server_names: [], short_ids: [] }
  return s.reality as Reality
})

const acme = computed(() => (form.value?.security.acme ?? null) as { domain: string, email?: string } | null)
function setAcme(on: boolean) {
  const sec = form.value!.security
  sec.acme = on ? { domain: String(sec.sni ?? ''), email: '' } : null
}
const certStates = computed(() => {
  const domain = acme.value?.domain
  return (daemon.value?.live.certs ?? []).filter(c => c.domain === domain)
})

const mux = computed(() => (form.value?.options.mux ?? null) as Mux | null)
function setMux(patch: Partial<Mux>) {
  form.value!.options = { ...form.value!.options, mux: { enabled: false, ...mux.value, ...patch } }
}

// Where each field lives, so an error on a hidden tab brings that tab forward.
function tabOf(path: string): string {
  if (path.startsWith('transport.') || path.startsWith('security.')) return 'transport'
  if (path.startsWith('options.') || path.startsWith('sniffing.')) return 'protocol'
  if (path === 'raw_patch') return 'advanced'
  return 'general'
}

function rulesOf(f: Form): Record<string, string | undefined> {
  const e: Record<string, Check> = {}
  e.tag = checkRequired(f.tag, 'Give it a tag') ?? (/\s/.test(f.tag) ? 'A tag can\'t contain spaces' : undefined)
  e.port = checkPort(f.port)
  if (f.listen) e.listen = checkIp(f.listen)
  if (f.edge_daemon_id) e.edge_sni = checkEach(f.edge_sni, checkServerName)

  if (f.protocol === 'forward') {
    const t = f.forward ?? { address: '', port: 0 }
    e['forward.address'] = checkRequired(t.address, 'Where should it forward to?') ?? checkHost(String(t.address))
    e['forward.port'] = checkPort(t.port)
    return problems(e)
  }

  const sec = f.security
  if (sec.type === 'reality') {
    const r = (sec.reality ?? {}) as Partial<Reality>
    e['security.reality.dest'] = checkRequired(r.dest, 'Pick a handshake target') ?? checkHostPort(String(r.dest))
    e['security.reality.server_names'] = checkRequired(r.server_names, 'Add at least one server name')
    e['security.reality.private_key'] = checkRequired(r.private_key, 'Generate a key pair')
    e['security.reality.short_ids'] = checkEach(r.short_ids, checkShortId)
  }
  else if (sec.type === 'tls') {
    const a = sec.acme as { domain?: string, email?: string } | null | undefined
    if (a) {
      e['security.acme.domain'] = checkRequired(a.domain, 'Which domain is the certificate for?') ?? checkDomain(String(a.domain))
      if (a.email) e['security.acme.email'] = checkEmail(a.email)
    }
    else {
      e['security.cert_path'] = checkRequired(sec.cert_path, 'Where is the certificate file?')
      e['security.key_path'] = checkRequired(sec.key_path, 'Where is the key file?')
    }
  }

  const o = f.options
  switch (f.protocol) {
    case 'turnable': {
      e['options.t_call_id'] = checkRequired(o.t_call_id, 'Paste the call id from the VK link')
      e['options.t_peers'] = o.t_peers ? checkInt(o.t_peers, 0, 64) : undefined
      e['options.t_public'] = checkRequired(o.t_public, 'Generate a key pair')
      e['options.t_private'] = checkRequired(o.t_private, 'Generate a key pair')
      const routes = (o.t_routes ?? []) as TurnableRoute[]
      if (!routes.length) e['options.t_routes'] = 'Add at least one destination'
      routes.forEach((r, i) => {
        const at = (k: string) => `options.t_routes.${i}.${k}`
        e[at('id')] = !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(r.id) ? 'Use lowercase letters, digits, - and _, up to 32 characters'
          : routes.findIndex(x => x.id === r.id) !== i ? 'Another destination already uses this id' : undefined
        e[at('target')] = checkRequired(r.target, 'Where does it lead?') ?? checkHostPort(r.target, { ipOnly: true })
        if (r.socket === 'tcp' && r.transport === 'none') e[at('transport')] = 'TCP needs a transport other than none'
      })
      break
    }
    case 'wireguard':
      e['options.wg_subnet'] = checkRequired(o.wg_subnet, 'Pick a subnet for the tunnel') ?? checkCidr(String(o.wg_subnet))
      e['options.wg_private'] = checkRequired(o.wg_private, 'Generate a key pair')
      if (o.wg_mtu) e['options.wg_mtu'] = checkInt(o.wg_mtu, 576, 9000)
      break
    case 'mtproto':
      if ((o.mt_mode || 'faketls') === 'faketls') e['options.mt_domain'] = checkRequired(o.mt_domain, 'Pick a cover site') ?? checkDomain(String(o.mt_domain))
      break
    case 'shadowtls':
      e['options.handshake'] = checkRequired(o.handshake, 'Pick a handshake server') ?? checkHostPort(String(o.handshake))
      break
    case 'shadowsocks':
      if (String(o.method ?? '').startsWith('2022-')) e['options.server_key'] = checkRequired(o.server_key, 'Generate a server key')
      break
    case 'hysteria2':
    case 'tuic':
      if (o.ports && !/^\d{1,5}-\d{1,5}$/.test(String(o.ports))) e['options.ports'] = 'Use a range like 20000-30000'
      break
  }
  return problems(e)
}

const formApi = useForm(form, rulesOf, { reveal: path => (tab.value = tabOf(path)) })

const testResult = ref<CommandResult | null>(null)
const { loading: testing, run: testDest } = useAsyncAction(async () => {
  try {
    testResult.value = await useApi<CommandResult>('/tools/test-reality', { method: 'POST', body: { daemon_id: form.value!.daemon_id, dest: reality.value?.dest } })
  }
  catch (e) {
    testResult.value = { id: 0, ok: false, error: errorMessage(e) }
  }
})

async function newKeys() {
  const k = await useApi<{ private: string, public: string }>('/tools/keys', { method: 'POST', body: { type: 'reality' } })
  reality.value!.private_key = k.private
  reality.value!.public_key = k.public
}

async function newShortId() {
  const r = await useApi<{ short_id: string }>('/tools/keys', { method: 'POST', body: { type: 'short_id' } })
  reality.value!.short_ids = [...reality.value!.short_ids, r.short_id]
}

async function newSsKey() {
  const r = await useApi<{ key: string }>('/tools/keys', { method: 'POST', body: { type: 'ss2022', method: form.value!.options.method } })
  form.value!.options = { ...form.value!.options, server_key: r.key }
}

const { loading: saving, run: save } = useAsyncAction(async () => {
  const fm = form.value!
  const body = { ...fm, forward: fm.protocol === 'forward' ? fm.forward : null }
  if (props.id) {
    await useApi(`/inbounds/${props.id}`, { method: 'PUT', body })
    await reload()
    return
  }
  const created = await useApi<Inbound>('/inbounds', { method: 'POST', body })
  await refreshNuxtData('inbounds')
  useSideDrawer().open('inbound', created.id)
}, 'Saved.', formApi)

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/inbounds/${props.id}`, { method: 'DELETE' })
  await refreshNuxtData('inbounds')
  emit('done')
}, 'Inbound deleted.')
</script>
