<template>
  <AppModal :title="preset ? preset.label : 'New inbound'" :subtitle="preset ? preset.description : 'Pick a recipe. You can fine tune everything afterwards.'" max-width="max-w-3xl" @close="emit('close')">
    <div class="mb-4">
      <FormField label="Create it on">
        <select v-model.number="daemonId" class="select w-full">
          <optgroup v-for="n in nodes.filter(n => n.daemons.some(d => d.kind !== 'edge'))" :key="n.id" :label="`${flag(n.country)} ${n.name}`">
            <option v-for="d in n.daemons.filter(d => d.kind !== 'edge')" :key="d.id" :value="d.id">{{ d.name }} ({{ coreLabels[d.kind] ?? d.kind }})</option>
          </optgroup>
        </select>
      </FormField>
    </div>

    <template v-if="!preset">
      <Skeleton v-if="!presets" :rows="3" :height="80" />
      <template v-else>
        <div v-for="g in groups" :key="g.name" class="mb-4">
          <p class="text-base-content/50 mb-2 text-xs font-semibold tracking-wide uppercase">{{ $t(g.name) }}</p>
          <div class="grid gap-2 sm:grid-cols-2">
            <button v-for="p in g.items" :key="p.id" type="button" class="surface hover:border-primary/60 flex flex-col gap-0.5 p-3 text-left transition" @click="choose(p)">
              <span class="font-medium">{{ $t(p.label) }}</span>
              <span class="text-base-content/60 text-xs">{{ $t(p.description) }}</span>
            </button>
          </div>
        </div>
        <p v-if="!groups.length" class="text-base-content/60 text-sm">{{ $t('This core has no recipes yet.') }}</p>
        <div class="divider text-xs">{{ $t('or') }}</div>
        <button type="button" class="btn btn-sm btn-ghost" @click="custom"><Icon name="fa6-solid:screwdriver-wrench" size="12" /> {{ $t('Start from a blank inbound') }}</button>
      </template>
    </template>

    <form v-else id="preset" class="flex flex-col gap-3" @submit.prevent="create">
      <div class="grid gap-3 sm:grid-cols-2">
        <FormField v-for="p in preset.params" :key="p.key" :label="p.label" :hint="p.hint">
          <input v-model="values[p.key]" :type="p.kind === 'number' ? 'number' : 'text'" class="input w-full" :placeholder="p.default">
        </FormField>
      </div>
      <div v-if="preset.id.includes('reality')" class="flex items-center gap-2">
        <button type="button" class="btn btn-sm" :class="{ 'btn-disabled': testing }" @click="test"><Icon name="fa6-solid:vial" size="12" /> {{ $t('Test the handshake target') }}</button>
        <span v-if="testResult" class="text-xs" :class="testResult.ok ? 'text-success' : 'text-error'">{{ testResult.ok ? testResult.output : testResult.error }}</span>
      </div>
      <p v-if="needsCert" class="text-base-content/60 text-xs">
        {{ $t('No certificate on the node yet? Leave the paths as they are. The daemon creates a self signed one so it can start, and you can drop a real one at the same place later.') }}
      </p>
    </form>

    <template v-if="preset" #footer>
      <div class="flex items-center justify-between gap-2">
        <button type="button" class="btn btn-ghost" @click="preset = null"><Icon name="fa6-solid:arrow-left" size="12" /> {{ $t('Back') }}</button>
        <button form="preset" class="btn btn-primary" :class="{ 'btn-disabled': saving }"><span v-if="saving" class="loading loading-spinner loading-xs" /> {{ $t('Create inbound') }}</button>
      </div>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import type { CommandResult, Inbound, PanelNode, Preset } from '~/types/api'

const props = defineProps<{ nodes: PanelNode[], daemonId: number | null }>()
const emit = defineEmits<{ close: [], created: [i: Inbound] }>()
const side = useSideDrawer()

const all = computed(() => props.nodes.flatMap(n => n.daemons).filter(d => d.kind !== 'edge'))
const daemonId = ref(props.daemonId ?? all.value[0]?.id ?? 0)
const kind = computed(() => all.value.find(d => d.id === daemonId.value)?.kind ?? '')

const { data: presets } = useAsyncData('presets', () => useApi<Preset[]>('/presets'))
const groups = computed(() => {
  const by = new Map<string, Preset[]>()
  for (const p of presets.value ?? []) {
    if (!p.cores.includes(kind.value)) continue
    by.set(p.group, [...(by.get(p.group) ?? []), p])
  }
  return [...by].map(([name, items]) => ({ name, items }))
})

const preset = ref<Preset | null>(null)
const values = ref<Record<string, string>>({})
const needsCert = computed(() => preset.value?.params.some(p => p.key === 'cert'))

function choose(p: Preset) {
  preset.value = p
  values.value = Object.fromEntries(p.params.map(prm => [prm.key, prm.default ?? '']))
}

function custom() {
  emit('close')
  side.open('inbound', null, { daemon: String(daemonId.value) })
}

const testResult = ref<CommandResult | null>(null)
const { loading: testing, run: test } = useAsyncAction(async () => {
  try {
    testResult.value = await useApi<CommandResult>('/tools/test-reality', { method: 'POST', body: { daemon_id: daemonId.value, dest: values.value.dest || preset.value?.params.find(p => p.key === 'dest')?.default } })
  }
  catch (e) {
    testResult.value = { id: 0, ok: false, error: errorMessage(e) }
  }
})

const { loading: saving, run: create } = useAsyncAction(async () => {
  const params: Record<string, unknown> = {}
  for (const p of preset.value!.params) {
    const v = values.value[p.key]
    if (v !== '' && v !== undefined) params[p.key] = p.kind === 'number' ? Number(v) : v
  }
  const i = await useApi<Inbound>('/inbounds', { method: 'POST', body: { daemon_id: daemonId.value, preset: preset.value!.id, params } })
  emit('created', i)
}, 'Inbound created.')
</script>
