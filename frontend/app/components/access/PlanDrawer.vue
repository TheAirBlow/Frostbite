<template>
  <form class="flex flex-col gap-4" novalidate @submit.prevent="save()">
    <FormField label="Name" name="name" required><input v-model="form.name" class="input w-full" :placeholder="$t('Monthly 100 GB')"></FormField>
    <FormField label="Traffic" name="traffic_limit"><ByteInput v-model="form.traffic_limit" /></FormField>
    <div class="grid gap-3 sm:grid-cols-2">
      <FormField label="Valid for (days)" name="duration_days" hint="0 never expires."><input v-model.number="form.duration_days" type="number" min="0" class="input w-full"></FormField>
      <FormField label="Traffic resets" name="reset_strategy"><select v-model="form.reset_strategy" class="select w-full"><option v-for="(l, k) in resetLabels" :key="k" :value="k">{{ l }}</option></select></FormField>
    </div>
    <ToggleRow v-model="form.start_on_first_use" label="Start the clock on first use" hint="New users stay on hold until they connect for the first time." />
    <FormField label="Squads" name="squad_ids">
      <div class="flex flex-wrap gap-1.5">
        <button v-for="s in squads ?? []" :key="s.id" type="button" class="btn btn-sm rounded-full" :class="form.squad_ids.includes(s.id) ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="form.squad_ids = form.squad_ids.includes(s.id) ? form.squad_ids.filter(x => x !== s.id) : [...form.squad_ids, s.id]">{{ s.name }}</button>
      </div>
    </FormField>
    <Advanced>
      <div class="grid gap-3 sm:grid-cols-2">
        <FormField label="Device limit" name="device_limit"><input v-model.number="form.device_limit" type="number" min="0" class="input w-full"></FormField>
        <FormField label="Simultaneous IPs" name="ip_limit"><input v-model.number="form.ip_limit" type="number" min="0" class="input w-full"></FormField>
      </div>
      <FormField label="Note" name="note"><input v-model="form.note" class="input w-full"></FormField>
    </Advanced>

    <FormFooter>
      <ConfirmButton v-if="id" type="button" class="btn btn-ghost text-error" confirm-label="Delete plan?" @confirmed="remove"><Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}</ConfirmButton>
      <span v-else />
      <button class="btn btn-primary" :disabled="saving">{{ id ? 'Save changes' : 'Create plan' }}</button>
    </FormFooter>
  </form>
</template>

<script setup lang="ts">
import type { Plan, Squad } from '~/types/api'

const props = defineProps<{ id: number | null }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string }], done: [] }>()

const form = reactive({ name: '', traffic_limit: 0, duration_days: 30, reset_strategy: 'none', start_on_first_use: false, device_limit: 0, ip_limit: 0, squad_ids: [] as number[], note: '' })
const formApi = useForm(form, f => problems({
  name: checkRequired(f.name, 'Give the plan a name'),
  duration_days: checkInt(f.duration_days, 0, 36500, 'a number of days'),
  device_limit: checkInt(f.device_limit, 0, 1000),
  ip_limit: checkInt(f.ip_limit, 0, 1000),
}))
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
}, 'Saved.', formApi)

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/plans/${props.id}`, { method: 'DELETE' })
  emit('done')
}, 'Plan deleted.')
</script>
