<template>
  <form class="flex flex-col gap-4" novalidate @submit.prevent="save()">
    <FormField label="Name" name="name" required><input v-model="form.name" class="input w-full" :placeholder="$t('Europe')"></FormField>
    <FormField label="Note" name="note"><input v-model="form.note" class="input w-full"></FormField>

    <FormField label="Inbounds in this squad" name="inbound_ids" class="gap-2">
      <Skeleton v-if="!nodes" :rows="3" />
      <template v-else>
        <div v-for="n in nodes.filter(n => n.daemons.some(d => byDaemon(d.id).length))" :key="n.id" class="surface p-3">
          <p class="mb-2 font-medium">{{ flag(n.country) }} {{ n.name }}</p>
          <div class="flex flex-col gap-1">
            <template v-for="d in n.daemons" :key="d.id">
              <label v-for="i in byDaemon(d.id)" :key="i.id" class="hover:bg-base-300/40 flex cursor-pointer items-center gap-3 rounded-lg px-2 py-1.5">
                <input v-model="form.inbound_ids" type="checkbox" class="checkbox checkbox-sm checkbox-primary" :value="i.id">
                <span class="min-w-0 flex-1 truncate text-sm">{{ i.remark || i.tag }}</span>
                <span class="badge badge-xs badge-ghost">{{ protocolLabels[i.protocol] }}</span>
                <span class="text-base-content/50 font-mono text-xs">:{{ i.port }}</span>
              </label>
            </template>
          </div>
        </div>
        <p v-if="!inbounds?.length" class="text-base-content/50 text-sm">{{ $t('There are no inbounds yet. Create some first.') }}</p>
        <div class="flex gap-1">
          <button type="button" class="btn btn-xs" @click="form.inbound_ids = (inbounds ?? []).filter(i => i.protocol !== 'forward').map(i => i.id)">{{ $t('Select all') }}</button>
          <button type="button" class="btn btn-xs" @click="form.inbound_ids = []">{{ $t('Clear') }}</button>
        </div>
      </template>
    </FormField>

    <FormFooter>
      <ConfirmButton v-if="id" type="button" class="btn btn-ghost text-error" confirm-label="Delete squad?" @confirmed="remove"><Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}</ConfirmButton>
      <span v-else />
      <button class="btn btn-primary" :disabled="saving">{{ id ? 'Save changes' : 'Create squad' }}</button>
    </FormFooter>
  </form>
</template>

<script setup lang="ts">
import type { Inbound, PanelNode, Squad } from '~/types/api'

const props = defineProps<{ id: number | null }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string }], done: [] }>()

const form = reactive({ name: '', note: '', inbound_ids: [] as number[] })
const formApi = useForm(form, f => problems({ name: checkRequired(f.name, 'Give the squad a name') }))
const { data: nodes } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'))
const { data: inbounds } = useAsyncData('inbounds', () => useApi<Inbound[]>('/inbounds'))
const byDaemon = (daemonId: number) => (inbounds.value ?? []).filter(i => i.daemon_id === daemonId && i.protocol !== 'forward')

emit('title', { title: props.id ? 'Squad' : 'New squad' })
onMounted(async () => {
  if (!props.id) return
  const s = (await useApi<Squad[]>('/squads')).find(x => x.id === props.id)
  if (!s) return
  Object.assign(form, { name: s.name, note: s.note, inbound_ids: [...s.inbound_ids] })
  emit('title', { title: s.name, subtitle: `${s.users} members` })
})

const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi(props.id ? `/squads/${props.id}` : '/squads', { method: props.id ? 'PUT' : 'POST', body: { ...form } })
  emit('done')
}, 'Saved.', formApi)

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/squads/${props.id}`, { method: 'DELETE' })
  emit('done')
}, 'Squad deleted.')
</script>
