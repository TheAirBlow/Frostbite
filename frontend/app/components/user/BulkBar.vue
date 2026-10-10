<template>
  <Teleport to="body">
    <div class="fixed inset-x-0 bottom-20 z-40 flex justify-center px-3 sm:bottom-6 sm:pl-20">
      <div class="bg-base-200 border-base-300 flex max-w-full flex-wrap items-center gap-1.5 rounded-2xl border p-2 shadow-2xl">
        <span class="px-2 text-sm font-medium">{{ ids.length }} selected</span>
        <button class="btn btn-sm btn-ghost" @click="ask('extend')"><Icon name="fa6-solid:calendar-plus" size="13" /> {{ $t('Extend') }}</button>
        <button class="btn btn-sm btn-ghost" @click="ask('add_traffic')"><Icon name="fa6-solid:database" size="13" /> {{ $t('Traffic') }}</button>
        <button class="btn btn-sm btn-ghost" @click="run('reset_traffic', {}, 'Traffic reset.')"><Icon name="fa6-solid:rotate-left" size="13" /> {{ $t('Reset') }}</button>
        <button class="btn btn-sm btn-ghost" @click="run('enable', {}, 'Enabled.')"><Icon name="fa6-solid:play" size="13" /> {{ $t('Enable') }}</button>
        <button class="btn btn-sm btn-ghost" @click="run('disable', {}, 'Disabled.')"><Icon name="fa6-solid:pause" size="13" /> {{ $t('Disable') }}</button>
        <button class="btn btn-sm btn-ghost" @click="ask('squads')"><Icon name="fa6-solid:layer-group" size="13" /> {{ $t('Squads') }}</button>
        <button class="btn btn-sm btn-ghost" @click="ask('tags')"><Icon name="fa6-solid:tags" size="13" /> {{ $t('Tags') }}</button>
        <ConfirmButton class="btn btn-sm btn-ghost text-error" confirm-label="Delete them?" @confirmed="run('delete', {}, 'Deleted.')">
          <Icon name="fa6-solid:trash" size="13" /> {{ $t('Delete') }}
        </ConfirmButton>
        <button class="btn btn-sm btn-circle btn-ghost" :aria-label="$t('Clear selection')" @click="emit('clear')"><Icon name="fa6-solid:xmark" size="13" /></button>
      </div>
    </div>
  </Teleport>

  <AppModal v-if="dialog" :title="titles[dialog]" max-width="max-w-md" @close="dialog = null">
    <form id="bulk" class="flex flex-col gap-3" @submit.prevent="submit">
      <template v-if="dialog === 'extend'">
        <FormField label="Days to add" hint="Counts from today for users who already expired. Use a negative number to take days away.">
          <input v-model.number="days" type="number" class="input w-full" required>
        </FormField>
        <div class="flex gap-1"><button v-for="d in [7, 30, 90, 365]" :key="d" type="button" class="btn btn-xs rounded-full" @click="days = d">{{ d }}d</button></div>
      </template>
      <template v-else-if="dialog === 'add_traffic'">
        <FormField label="Traffic to add" hint="Only touches users that have a limit. Users who hit it come back online."><ByteInput v-model="bytes" :allow-unlimited="false" /></FormField>
      </template>
      <template v-else-if="dialog === 'squads'">
        <Segmented v-model="squadMode" :options="[{ value: 'add_squads', label: 'Add to' }, { value: 'set_squads', label: 'Replace with' }]" />
        <div class="flex flex-wrap gap-1.5">
          <button v-for="s in squads" :key="s.id" type="button" class="btn btn-sm rounded-full" :class="squadIds.includes(s.id) ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="squadIds = squadIds.includes(s.id) ? squadIds.filter(x => x !== s.id) : [...squadIds, s.id]">{{ s.name }}</button>
        </div>
      </template>
      <template v-else>
        <FormField label="Tags to add"><ChipInput v-model="tags" :placeholder="$t('Add tags, press enter')" /></FormField>
      </template>
    </form>
    <template #footer>
      <div class="flex justify-end"><button form="bulk" class="btn btn-primary" :class="{ 'btn-disabled': working }">Apply to {{ ids.length }} users</button></div>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import type { Squad } from '~/types/api'

const props = defineProps<{ ids: number[], squads: Squad[] }>()
const emit = defineEmits<{ clear: [], done: [] }>()

type Dialog = 'extend' | 'add_traffic' | 'squads' | 'tags'
const dialog = ref<Dialog | null>(null)
const titles: Record<Dialog, string> = { extend: 'Extend validity', add_traffic: 'Add traffic', squads: 'Change squads', tags: 'Add tags' }

const days = ref(30)
const bytes = ref(10 * 1024 ** 3)
const squadMode = ref('add_squads')
const squadIds = ref<number[]>([])
const tags = ref<string[]>([])

function ask(d: Dialog) {
  dialog.value = d
}

const { loading: working, run: exec } = useAsyncAction(async (action: string, extra: Record<string, unknown>, ok?: string) => {
  await useApi('/users/bulk', { method: 'POST', body: { action, ids: props.ids, ...extra } })
  void ok
  emit('done')
})

const toast = useToast()
async function run(action: string, extra: Record<string, unknown>, message: string) {
  await exec(action, extra)
  toast.success(message)
}

async function submit() {
  switch (dialog.value) {
    case 'extend': await run('extend', { days: days.value }, 'Validity extended.'); break
    case 'add_traffic': await run('add_traffic', { bytes: bytes.value }, 'Traffic added.'); break
    case 'squads': await run(squadMode.value, { squad_ids: squadIds.value }, 'Squads updated.'); break
    case 'tags': await run('add_tags', { tags: tags.value }, 'Tags added.'); break
  }
  dialog.value = null
}
</script>
