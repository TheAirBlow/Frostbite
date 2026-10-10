<template>
  <AppModal :title="titles[step]" :subtitle="subtitles[step]" max-width="max-w-3xl" @close="modal.close">
    <!-- 1: what kind -->
    <div v-if="step === 0" class="grid gap-3 sm:grid-cols-2">
      <button v-for="k in kinds" :key="k.id" type="button" class="surface hover:border-primary/60 flex flex-col gap-2 p-4 text-left transition" @click="kind = k.id; step = 1">
        <span class="bg-primary/15 text-primary grid size-10 place-items-center rounded-xl"><Icon :name="k.icon" size="18" /></span>
        <span class="font-display text-xl font-semibold">{{ k.title }}</span>
        <span class="text-base-content/70 text-sm">{{ k.text }}</span>
        <ul class="text-base-content/60 list-disc pl-5 text-xs"><li v-for="p in k.points" :key="p">{{ p }}</li></ul>
      </button>
    </div>

    <!-- 2: details -->
    <form v-else-if="step === 1" id="bridge-form" class="flex flex-col gap-4" novalidate @submit.prevent="review">
      <FormField label="Where does the bridge run?" name="bridge_daemon_id" required>
        <select v-model.number="form.bridge_daemon_id" class="select w-full">
          <optgroup v-for="n in nodes" :key="n.id" :label="`${flag(n.country)} ${n.name}`"><option v-for="d in n.daemons" :key="d.id" :value="d.id">{{ d.name }} ({{ coreLabels[d.kind] ?? d.kind }})</option></optgroup>
        </select>
      </FormField>

      <template v-if="kind === 'relay'">
        <FormField label="Forward to" name="target_inbound_id" hint="Clients keep using the target's own keys. The relay just passes bytes along." required>
          <select v-model.number="form.target_inbound_id" class="select w-full">
            <option :value="null" disabled>{{ $t('Pick an inbound') }}</option>
            <optgroup v-for="n in nodes" :key="n.id" :label="`${flag(n.country)} ${n.name}`">
              <template v-for="d in n.daemons" :key="d.id"><option v-for="i in inboundsOf(d.id)" :key="i.id" :value="i.id" :disabled="d.id === form.bridge_daemon_id">{{ i.remark || i.tag }} · {{ protocolLabels[i.protocol] }}:{{ i.port }}</option></template>
            </optgroup>
          </select>
        </FormField>
        <FormField label="Listen on port" name="port" required><input v-model.number="form.port" type="number" min="1" max="65535" class="input w-full"></FormField>
        <FormField label="Name in subscriptions" name="name" hint="Optional. The default is the target's name plus 'via' and this node."><input v-model="form.name" class="input w-full"></FormField>
      </template>

      <template v-else>
        <FormField label="Exit through">
          <Segmented v-model="exitMode" :options="[{ value: 'inbound', label: 'One of my servers', icon: 'fa6-solid:server' }, { value: 'link', label: 'A share link', icon: 'fa6-solid:paste' }]" />
        </FormField>
        <FormField v-if="exitMode === 'inbound'" label="Exit inbound" name="target_inbound_id" hint="The bridge logs in to it with credentials Frostbite creates for it." required>
          <select v-model.number="form.target_inbound_id" class="select w-full">
            <option :value="null" disabled>{{ $t('Pick an inbound') }}</option>
            <optgroup v-for="n in nodes" :key="n.id" :label="`${flag(n.country)} ${n.name}`">
              <template v-for="d in n.daemons" :key="d.id"><option v-for="i in inboundsOf(d.id)" :key="i.id" :value="i.id" :disabled="d.id === form.bridge_daemon_id">{{ i.remark || i.tag }} · {{ protocolLabels[i.protocol] }}:{{ i.port }}</option></template>
            </optgroup>
          </select>
        </FormField>
        <FormField v-else label="Share link" name="link" hint="Any vless, vmess, trojan, ss, hysteria2, tuic or anytls link. Your own, or a provider's." required><textarea v-model="form.link" class="textarea w-full font-mono text-xs" rows="3" :placeholder="$t('vless://…')" /></FormField>

        <FormField label="Name" name="name" hint="A short label, used in tags."><input v-model="form.name" class="input w-full" :placeholder="$t('frankfurt')"></FormField>

        <div class="divider my-0">{{ $t('What the bridge accepts') }}</div>
        <div class="grid gap-3 sm:grid-cols-2">
          <FormField label="Recipe" name="preset" required>
            <select v-model="form.preset" class="select w-full"><option v-for="p in presetChoices" :key="p.id" :value="p.id">{{ p.label }}</option></select>
          </FormField>
          <FormField v-for="p in currentPreset?.params ?? []" :key="p.key" :label="p.label" :hint="p.hint" :name="`params.${p.key}`">
            <input v-model="values[p.key]" :type="p.kind === 'number' ? 'number' : 'text'" class="input w-full" :placeholder="p.default">
          </FormField>
        </div>
        <ToggleRow v-model="form.everyone" label="Send all of this daemon's traffic through the exit" hint="Otherwise only users of the new inbound go through it." />
      </template>
    </form>

    <!-- 3: review / result -->
    <div v-else-if="step === 2" class="flex flex-col gap-4">
      <div class="surface from-primary/10 to-secondary/10 bg-gradient-to-br p-4">
        <p class="text-base-content/60 text-xs font-semibold tracking-wide uppercase">{{ $t('What will happen') }}</p>
        <p class="mt-1 text-lg">{{ sentence }}</p>
      </div>
      <ul class="text-base-content/70 list-disc pl-5 text-sm">
        <li v-if="kind === 'relay'">{{ $t('Users who can reach the target inbound see an extra profile that goes through the relay. Nothing to configure on their side.') }}</li>
        <template v-else>
          <li>{{ $t('A new inbound appears on the bridge. Put it in a squad to let users in.') }}</li>
          <li>{{ $t('Its traffic leaves through the exit you picked. Keys for chained servers are managed for you.') }}</li>
        </template>
      </ul>
    </div>

    <div v-else class="flex flex-col items-center gap-3 py-6 text-center">
      <span class="bg-success/15 text-success grid size-14 place-items-center rounded-2xl"><Icon name="fa6-solid:check" size="24" /></span>
      <p class="font-display text-xl font-semibold">{{ $t('Bridge created') }}</p>
      <p class="text-base-content/60 max-w-md text-sm">{{ kind === 'relay' ? 'The relay is listening. It shows up as a host of the target inbound.' : 'The bridge inbound is ready. Add it to a squad so users can connect.' }}</p>
      <div class="flex gap-2">
        <button class="btn btn-primary btn-sm" @click="finish">{{ $t('Done') }}</button>
        <NuxtLink v-if="kind === 'chain'" to="/access" class="btn btn-sm" @click="modal.close()">{{ $t('Open squads') }}</NuxtLink>
      </div>
    </div>

    <template v-if="step === 1 || step === 2" #footer>
      <FormBanner class="mb-2" />
      <div class="flex items-center justify-between gap-2">
        <button type="button" class="btn btn-ghost" @click="step--"><Icon name="fa6-solid:arrow-left" size="12" /> {{ $t('Back') }}</button>
        <button v-if="step === 1" form="bridge-form" class="btn btn-primary">{{ $t('Review') }}</button>
        <button v-else class="btn btn-primary" :disabled="saving" @click="create()"><span v-if="saving" class="loading loading-spinner loading-xs" /> {{ $t('Create bridge') }}</button>
      </div>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import type { Inbound, PanelNode, Preset } from '~/types/api'

const modal = useDrawer()
const step = ref(0)
const kind = ref<'relay' | 'chain'>('relay')
const exitMode = ref('inbound')

const titles = computed(() => ['New bridge', kind.value === 'relay' ? 'New relay' : 'New chain', 'Review', 'Done'])
const subtitles = ['What kind of bridge do you need?', 'A few details', 'Take a last look', '']

const kinds = [
  { id: 'relay' as const, title: 'Relay', icon: 'fa6-solid:right-left', text: 'A small forwarder on another server that passes traffic straight to one of your inbounds.', points: ['Needs no users or keys of its own', 'Hides the real server behind a different IP', 'Works for any protocol, even UDP ones'] },
  { id: 'chain' as const, title: 'Chain', icon: 'fa6-solid:link', text: 'A full server with its own users, whose traffic leaves through a different server or any proxy you have.', points: ['Entry and exit can be in different countries', 'Exit can be a share link from anywhere', 'Combine with routing rules for split exits'] },
]

const { data: nodes } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'), { default: () => [] })
const { data: inbounds } = useAsyncData('inbounds', () => useApi<Inbound[]>('/inbounds'), { default: () => [] })
const { data: presets } = useAsyncData('presets', () => useApi<Preset[]>('/presets'), { default: () => [] })

const all = computed(() => nodes.value.flatMap(n => n.daemons))
const form = reactive({ bridge_daemon_id: 0, target_inbound_id: null as number | null, port: 443, name: '', link: '', preset: 'vless-reality', everyone: false })
const values = ref<Record<string, string>>({})
watch(all, (d) => {
  if (!form.bridge_daemon_id && d.length) form.bridge_daemon_id = d[0]!.id
}, { immediate: true })

const inboundsOf = (daemonId: number) => inbounds.value.filter(i => i.daemon_id === daemonId && i.protocol !== 'forward')
const bridgeKind = computed(() => all.value.find(d => d.id === form.bridge_daemon_id)?.kind ?? '')
const presetChoices = computed(() => presets.value.filter(p => p.cores.includes(bridgeKind.value)))
const currentPreset = computed(() => presetChoices.value.find(p => p.id === form.preset))
watch([presetChoices, () => form.preset], () => {
  if (!currentPreset.value && presetChoices.value.length) form.preset = presetChoices.value[0]!.id
  values.value = Object.fromEntries((currentPreset.value?.params ?? []).map(p => [p.key, p.default ?? '']))
}, { immediate: true })

const nodeOf = (daemonId: number) => nodes.value.find(n => n.daemons.some(d => d.id === daemonId))
const sentence = computed(() => {
  const bridge = nodeOf(form.bridge_daemon_id)?.name ?? 'the bridge'
  const target = inbounds.value.find(i => i.id === form.target_inbound_id)
  const targetNode = target ? nodeOf(target.daemon_id)?.name : ''
  if (kind.value === 'relay') return `Clients connect to ${bridge} on port ${form.port}, which forwards everything to ${target?.remark || target?.tag} on ${targetNode}.`
  const exit = exitMode.value === 'inbound' ? `${target?.remark || target?.tag} on ${targetNode}` : 'the proxy from your share link'
  return `${bridge} accepts ${currentPreset.value?.label ?? 'connections'} and sends the traffic out through ${exit}.`
})

// a rejected request sends the person back to the step that holds the field
const formApi = useForm(form, (f) => {
  const e: Record<string, Check> = { bridge_daemon_id: f.bridge_daemon_id ? undefined : 'Pick where the bridge runs' }
  if (kind.value === 'relay') {
    e.target_inbound_id = f.target_inbound_id ? undefined : 'Pick the inbound to forward to'
    e.port = checkPort(f.port)
  }
  else {
    if (exitMode.value === 'inbound') e.target_inbound_id = f.target_inbound_id ? undefined : 'Pick the inbound to exit through'
    else e.link = checkRequired(f.link, 'Paste a share link') ?? (/^[a-z0-9+.-]+:\/\/\S+$/i.test(f.link.trim()) ? undefined : 'That does not look like a share link, such as vless://…')
    e.preset = f.preset ? undefined : 'Pick a recipe'
    for (const p of currentPreset.value?.params ?? []) {
      const v = values.value[p.key]
      if (p.key === 'port') e[`params.${p.key}`] = checkPort(v || p.default)
      else if (p.kind === 'number' && v) e[`params.${p.key}`] = checkInt(v, 0, undefined, 'a number')
    }
  }
  return problems(e)
}, { reveal: () => { if (step.value > 1) step.value = 1 } })

function review() {
  if (formApi.validate()) step.value = 2
}

const { loading: saving, run: create } = useAsyncAction(async () => {
  const params: Record<string, unknown> = {}
  for (const p of currentPreset.value?.params ?? []) {
    if (values.value[p.key] !== '' && values.value[p.key] !== undefined) params[p.key] = p.kind === 'number' ? Number(values.value[p.key]) : values.value[p.key]
  }
  const body: Record<string, unknown> = { kind: kind.value, name: form.name, bridge_daemon_id: form.bridge_daemon_id }
  if (kind.value === 'relay') Object.assign(body, { target_inbound_id: form.target_inbound_id, port: form.port })
  else Object.assign(body, { preset: form.preset, params, everyone: form.everyone, target_inbound_id: exitMode.value === 'inbound' ? form.target_inbound_id : null, link: exitMode.value === 'link' ? form.link : '' })
  await useApi('/bridges', { method: 'POST', body })
  await refreshNuxtData()
  step.value = 3
}, undefined, formApi)

function finish() {
  modal.close()
}
</script>
