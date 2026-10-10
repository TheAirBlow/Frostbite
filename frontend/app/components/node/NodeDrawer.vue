<template>
  <form class="flex flex-col gap-4" novalidate @submit.prevent="save()">
    <div class="grid gap-3 sm:grid-cols-2">
      <FormField label="Name" name="name" required><input v-model="form.name" class="input w-full" :placeholder="$t('Frankfurt')"></FormField>
      <FormField label="Country" name="country">
        <select v-model="form.country" class="select w-full">
          <option value="">{{ $t('Unknown') }}</option>
          <option v-for="(name, code) in countries" :key="code" :value="code">{{ flag(code) }} {{ name }}</option>
        </select>
      </FormField>
    </div>
    <FormField label="Address" name="address" required hint="The domain or IP clients connect to. It also goes into every share link of this node.">
      <input v-model="form.address" class="input w-full font-mono" :placeholder="$t('de1.example.com')" autocomplete="off">
    </FormField>
    <FormField label="Tags" name="tags"><ChipInput v-model="form.tags" :placeholder="$t('premium, eu, ...')" /></FormField>
    <FormField label="Traffic limit" name="traffic_limit" hint="Informational, shown as a bar on the node card."><ByteInput v-model="form.traffic_limit" /></FormField>
    <FormField label="Traffic multiplier" name="traffic_multiplier" hint="Usage on this node is multiplied before it counts against users. 2 means everything costs double, 0 makes it free.">
      <div class="flex items-center gap-2">
        <input v-model.number="form.traffic_multiplier" type="number" min="0" step="0.1" class="input w-28">
        <button v-for="m in [0, 0.5, 1, 2]" :key="m" type="button" class="btn btn-xs rounded-full" :class="form.traffic_multiplier === m ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="form.traffic_multiplier = m">×{{ m }}</button>
      </div>
    </FormField>
    <FormField label="Note" name="note"><textarea v-model="form.note" class="textarea w-full" rows="2" /></FormField>
    <ToggleRow v-model="form.enabled" label="Enabled" hint="A disabled node disappears from subscriptions." />
    <Advanced><FormField label="Sort order" name="sort" hint="Lower comes first in subscriptions."><input v-model.number="form.sort" type="number" class="input w-28"></FormField></Advanced>

    <FormFooter>
      <ConfirmButton v-if="id" type="button" class="btn btn-ghost text-error" confirm-label="Delete node and its daemons?" @confirmed="remove"><Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}</ConfirmButton>
      <span v-else />
      <button class="btn btn-primary" :disabled="saving"><span v-if="saving" class="loading loading-spinner loading-xs" /> {{ id ? 'Save changes' : 'Add node' }}</button>
    </FormFooter>
  </form>
</template>

<script setup lang="ts">
import type { PanelNode } from '~/types/api'

const props = defineProps<{ id: number | null }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string }], done: [] }>()

const form = reactive({ name: '', address: '', country: '', tags: [] as string[], traffic_multiplier: 1, traffic_limit: 0, note: '', enabled: true, sort: 0 })

const formApi = useForm(form, f => problems({
  name: checkRequired(f.name, 'Give the node a name'),
  address: checkRequired(f.address, 'Enter the address clients connect to') ?? checkHost(f.address),
  traffic_multiplier: Number.isFinite(f.traffic_multiplier) && f.traffic_multiplier >= 0 ? undefined : 'Enter a multiplier, 0 or more',
  traffic_limit: f.traffic_limit < 0 ? 'It can\'t be negative' : undefined,
}))

emit('title', { title: props.id ? 'Edit node' : 'New node' })

onMounted(async () => {
  if (!props.id) return
  const nodes = await useApi<PanelNode[]>('/nodes')
  const n = nodes.find(x => x.id === props.id)
  if (!n) return
  Object.assign(form, { name: n.name, address: n.address, country: n.country, tags: n.tags, traffic_multiplier: n.traffic_multiplier, traffic_limit: n.traffic_limit, note: n.note, enabled: n.enabled, sort: n.sort })
  emit('title', { title: n.name, subtitle: n.address })
})

const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi(props.id ? `/nodes/${props.id}` : '/nodes', { method: props.id ? 'PUT' : 'POST', body: { ...form } })
  await refreshNuxtData()
  emit('done')
}, 'Saved.', formApi)

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/nodes/${props.id}`, { method: 'DELETE' })
  await refreshNuxtData()
  emit('done')
}, 'Node deleted.')
</script>
