<template>
  <section class="surface flex flex-col gap-3 p-4">
    <header class="flex items-start justify-between gap-3">
      <div>
        <h4 class="text-base-content/70 text-sm font-semibold tracking-wide uppercase">{{ $t('Destinations') }}</h4>
        <p class="text-base-content/60 mt-0.5 text-xs">{{ $t('Where the tunnel can lead.') }}</p>
      </div>
      <button type="button" class="btn btn-sm shrink-0" @click="add"><Icon name="fa6-solid:plus" size="11" /> {{ $t('Add') }}</button>
    </header>

    <p v-if="!model.length" class="text-warning text-sm" data-field="options.t_routes" :data-field-error="rootError ? '' : undefined">{{ rootError ? $t(rootError) : $t('No destinations yet. Without one the tunnel leads nowhere.') }}</p>

    <article v-for="(r, i) in model" :key="i" class="bg-base-100 border-base-300 flex flex-col gap-3 rounded-xl border p-3">
      <div class="flex items-center gap-2">
        <span class="badge badge-primary badge-soft font-mono">{{ r.id || '?' }}</span>
        <span class="text-base-content/60 min-w-0 flex-1 truncate text-sm">{{ r.name || r.target || $t('New destination') }}</span>
        <button type="button" class="btn btn-ghost btn-xs btn-square text-error" :disabled="model.length === 1" :title="model.length === 1 ? $t('A tunnel needs at least one destination') : $t('Remove')" :aria-label="$t('Remove')" @click="remove(i)">
          <Icon name="fa6-solid:trash" size="12" />
        </button>
      </div>

      <div class="grid gap-3 sm:grid-cols-5">
        <FormField class="sm:col-span-3" label="Destination" :name="`options.t_routes.${i}.target`" required>
          <input v-model="r.target" class="input w-full font-mono" placeholder="127.0.0.1:51820" inputmode="url" autocomplete="off" :readonly="kindOf(r) === 'inbound'">
        </FormField>
        <FormField class="sm:col-span-2" label="Network" :name="`options.t_routes.${i}.socket`" required>
          <select v-model="r.socket" class="select w-full">
            <option value="udp">{{ $t('UDP') }}</option>
            <option value="tcp">{{ $t('TCP') }}</option>
          </select>
        </FormField>
      </div>

      <div class="border-base-300 flex flex-col gap-3 border-t pt-3">
        <FormField label="What other apps get" :name="`options.t_routes.${i}.kind`" hint="Which destination other VPN apps get.">
          <select class="select w-full" :value="kindOf(r)" @change="setKind(r, ($event.target as HTMLSelectElement).value as Kind)">
            <option value="external">{{ $t('Nothing, only Turnable apps see it') }}</option>
            <option value="inbound">{{ $t('One of my inbounds') }}</option>
            <option value="custom">{{ $t('A link I write myself') }}</option>
          </select>
        </FormField>

        <FormField v-if="kindOf(r) === 'inbound'" label="Inbound" :name="`options.t_routes.${i}.inbound_id`" required>
          <select class="select w-full" :value="r.inbound_id ?? ''" @change="pickInbound(r, Number(($event.target as HTMLSelectElement).value))">
            <option value="" disabled>{{ $t('Pick an inbound') }}</option>
            <option v-for="c in candidates" :key="c.id" :value="c.id">{{ c.remark || c.tag }} · {{ protocolLabels[c.protocol] ?? c.protocol }} :{{ c.port }}</option>
          </select>
          <p v-if="!candidates.length" class="text-warning mt-1 text-xs">{{ $t('There is no other inbound on this node to lead to yet.') }}</p>
        </FormField>

        <FormField v-if="kindOf(r) === 'custom'" label="Link" :name="`options.t_routes.${i}.url`" required>
          <textarea v-model="r.url" class="textarea w-full font-mono text-xs" rows="3" spellcheck="false" placeholder="vless://{uuid}@{host}:{port}?type=tcp&security=none#{name}" />
        </FormField>
        <p v-if="kindOf(r) === 'custom'" class="text-base-content/60 -mt-2 text-xs">
          {{ $t('Placeholders:') }}
          <code v-for="v in placeholders" :key="v" class="bg-base-300/60 mx-0.5 rounded px-1 font-mono">{{ braced(v) }}</code>.
        </p>

        <FormField v-if="kindOf(r) !== 'external'" label="Port on the device" :name="`options.t_routes.${i}.local_port`" hint="Local port of the Turnable app." required>
          <input v-model.number="r.local_port" type="number" min="1" max="65535" class="input w-full" placeholder="10800">
        </FormField>
      </div>

      <Advanced :title="$t('Id, name and tunnel options')">
        <div class="grid gap-3 sm:grid-cols-2">
          <FormField label="Id" :name="`options.t_routes.${i}.id`" hint="Apps refer to the destination by this. Lowercase letters, digits, - and _." required>
            <input :value="r.id" class="input w-full font-mono" placeholder="wg" autocomplete="off" @input="r.id = ($event.target as HTMLInputElement).value.toLowerCase()">
          </FormField>
          <FormField label="Name" :name="`options.t_routes.${i}.name`" hint="Shown in the app. Empty uses the user's name.">
            <input v-model="r.name" class="input w-full">
          </FormField>
          <FormField label="Transport" :name="`options.t_routes.${i}.transport`" hint="How packets are carried inside the tunnel.">
            <select v-model="r.transport" class="select w-full">
              <option value="mpath">{{ $t('mpath, spreads over connections') }}</option>
              <option value="kcp">{{ $t('kcp, fast and lossy networks') }}</option>
              <option value="sctp">{{ $t('sctp') }}</option>
              <option value="none">{{ $t('none, raw datagrams (UDP only)') }}</option>
            </select>
          </FormField>
          <FormField label="Encryption" :name="`options.t_routes.${i}.encryption`" hint="Full also encrypts every packet after the handshake.">
            <select v-model="r.encryption" class="select w-full">
              <option value="handshake">{{ $t('handshake only') }}</option>
              <option value="full">{{ $t('full') }}</option>
            </select>
          </FormField>
        </div>
      </Advanced>
    </article>
  </section>
</template>

<script setup lang="ts">
import type { Inbound, PanelNode, TurnableRoute } from '~/types/api'

type Kind = NonNullable<TurnableRoute['kind']>

// `nodeId` is the node this inbound runs on: a tunnel only reaches inbounds next to it
const props = defineProps<{ nodeId?: number }>()
const model = defineModel<TurnableRoute[]>({ required: true })
const ctx = inject(formKey, null)

const placeholders = ['host', 'port', 'user', 'uuid', 'password', 'name', 'node', 'country', 'route']
const { data: nodes } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'))
const { data: inbounds } = useAsyncData('inbounds', () => useApi<Inbound[]>('/inbounds'))

// inbounds on this node that a tunnel can lead to: not relays, not other tunnels, not behind an edge
const candidates = computed(() => {
  const daemons = new Set((nodes.value ?? []).find(n => n.id === props.nodeId)?.daemons.map(d => d.id) ?? [])
  return (inbounds.value ?? []).filter(i => daemons.has(i.daemon_id) && !['forward', 'turnable', 'shadowtls'].includes(i.protocol) && !i.edge_daemon_id)
})

const kindOf = (r: TurnableRoute): Kind => r.kind || 'external'
const braced = (v: string) => `{${v}}`

function nextPort(): number {
  const used = new Set(model.value.map(r => r.local_port))
  let p = 10800
  while (used.has(p)) p++
  return p
}

function setKind(r: TurnableRoute, kind: Kind) {
  r.kind = kind
  if (kind !== 'external' && !r.local_port) r.local_port = nextPort()
  if (kind === 'custom' && !r.url) r.url = ''
}

function pickInbound(r: TurnableRoute, id: number) {
  const target = candidates.value.find(c => c.id === id)
  r.inbound_id = id
  if (target) {
    // the network follows what the inbound speaks
    const udp = ['hysteria2', 'tuic', 'wireguard'].includes(target.protocol) || target.transport?.type === 'kcp'
    r.socket = udp ? 'udp' : 'tcp'
    if (r.socket === 'tcp' && r.transport === 'none') r.transport = 'mpath'
  }
  if (target) r.target = `${!target.listen || ['0.0.0.0', '::'].includes(target.listen) ? '127.0.0.1' : target.listen}:${target.port}`
}
const rootError = computed(() => ctx?.error('options.t_routes') ?? '')

function add() {
  const taken = new Set(model.value.map(r => r.id))
  let n = model.value.length + 1
  while (taken.has(`route-${n}`)) n++
  model.value = [...model.value, { id: `route-${n}`, name: '', target: '', socket: 'udp', transport: 'mpath', encryption: 'handshake', kind: 'external' }]
}

function remove(i: number) {
  if (model.value.length > 1) model.value = model.value.filter((_, idx) => idx !== i)
}
</script>
