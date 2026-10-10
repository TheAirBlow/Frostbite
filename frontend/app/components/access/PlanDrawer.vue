<template>
  <form class="flex flex-col gap-4" @submit.prevent="save">
    <FormField label="Name"><input v-model="form.name" class="input w-full" :placeholder="$t('Monthly 100 GB')" required></FormField>
    <FormField label="Traffic"><ByteInput v-model="form.traffic_limit" /></FormField>
    <div class="grid gap-3 sm:grid-cols-2">
      <FormField label="Valid for (days)" hint="0 never expires."><input v-model.number="form.duration_days" type="number" min="0" class="input w-full"></FormField>
      <FormField label="Traffic resets"><select v-model="form.reset_strategy" class="select w-full"><option v-for="(l, k) in resetLabels" :key="k" :value="k">{{ l }}</option></select></FormField>
    </div>
    <ToggleRow v-model="form.start_on_first_use" label="Start the clock on first use" hint="New users stay on hold until they connect for the first time." />
    <FormField label="Squads">
      <div class="flex flex-wrap gap-1.5">
        <button v-for="s in squads ?? []" :key="s.id" type="button" class="btn btn-sm rounded-full" :class="form.squad_ids.includes(s.id) ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="form.squad_ids = form.squad_ids.includes(s.id) ? form.squad_ids.filter(x => x !== s.id) : [...form.squad_ids, s.id]">{{ s.name }}</button>
      </div>
    </FormField>
    <Advanced>
      <div class="grid gap-3 sm:grid-cols-2">
        <FormField label="Device limit"><input v-model.number="form.device_limit" type="number" min="0" class="input w-full"></FormField>
        <FormField label="Simultaneous IPs"><input v-model.number="form.ip_limit" type="number" min="0" class="input w-full"></FormField>
      </div>
      <FormField label="Note"><input v-model="form.note" class="input w-full"></FormField>
    </Advanced>

    <div class="bg-base-100 border-base-300 sticky bottom-0 -mx-4 -mb-4 flex items-center justify-between gap-2 border-t p-3">
      <ConfirmButton v-if="id" type="button" class="btn btn-ghost text-error" confirm-label="Delete plan?" @confirmed="remove"><Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}</ConfirmButton>
      <span v-else />
      <button class="btn btn-primary" :class="{ 'btn-disabled': saving }">{{ id ? 'Save changes' : 'Create plan' }}</button>
    </div>
  </form>
</template>

<script setup lang="ts">
import type { Plan, Squad } from '~/types/api'

const props = defineProps<{ id: number | null }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string }], done: [] }>()

const form = reactive({ name: '', traffic_limit: 0, duration_days: 30, reset_strategy: 'none', start_on_first_use: false, device_limit: 0, ip_limit: 0, squad_ids: [] as number[], note: '' })
const { data: squads } = useAsyncData('squads', () => useApi<Squad[]>('/squads'))

emit('title', { title: props.id ? 'Plan' : 'New plan' })
onMounted(async () => {
  if (!props.id) return
  const p = (await useApi<Plan[]>('/plans')).find(x => x.id === props.id)
  if (!p) return
  Object.assign(form, { ...p, squad_ids: [...p.squad_ids] })
  emit('title', { title: p.name })
})

const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi(props.id ? `/plans/${props.id}` : '/plans', { method: props.id ? 'PUT' : 'POST', body: { ...form } })
  emit('done')
}, 'Saved.')

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/plans/${props.id}`, { method: 'DELETE' })
  emit('done')
}, 'Plan deleted.')
</script>
