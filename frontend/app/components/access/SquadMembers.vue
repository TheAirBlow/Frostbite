<template>
  <div class="flex flex-col gap-2">
    <div class="relative">
      <input v-model="query" class="input input-sm w-full" :placeholder="$t('Find a user to add')" autocomplete="off">
      <div v-if="matches.length" class="surface absolute inset-x-0 top-full z-10 mt-1 flex flex-col p-1 shadow-lg">
        <button v-for="m in matches" :key="m.id" type="button" class="hover:bg-base-300/40 flex items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm" @click="add(m)">
          <span class="min-w-0 flex-1 truncate">{{ m.username }}</span>
          <Icon name="fa6-solid:plus" size="11" />
        </button>
      </div>
    </div>
    <Skeleton v-if="!members" :rows="2" />
    <p v-else-if="!members.length" class="text-base-content/50 text-sm">{{ $t('Nobody is in this squad yet.') }}</p>
    <div v-else class="flex max-h-64 flex-col gap-1 overflow-y-auto">
      <div v-for="u in members" :key="u.id" class="hover:bg-base-300/40 flex items-center gap-2 rounded-lg px-2 py-1">
        <span class="min-w-0 flex-1 truncate text-sm">{{ u.username }}</span>
        <span v-if="!u.manageable" class="badge badge-xs badge-ghost">{{ $t('access only') }}</span>
        <button type="button" class="btn btn-ghost btn-xs" :aria-label="$t('Remove')" @click="removeMember(u)"><Icon name="fa6-solid:xmark" size="12" /></button>
      </div>
    </div>
    <p v-if="total > (members?.length ?? 0)" class="text-base-content/50 text-xs">{{ $t('Showing the first {n}.', { n: members?.length ?? 0 }) }}</p>
  </div>
</template>

<script setup lang="ts">
import type { PanelUser, Squad } from '~/types/api'

interface Match { id: number, username: string, squad_ids: number[] }

const props = defineProps<{ squadId: number }>()
const emit = defineEmits<{ changed: [] }>()

const { data, refresh } = useAsyncData(`squad-members-${props.squadId}`, () =>
  useApi<{ items: PanelUser[], total: number }>(`/users?squad=${props.squadId}&sort=name&limit=200`))
const members = computed(() => data.value?.items)
const total = computed(() => data.value?.total ?? 0)

const query = ref('')
const found = ref<Match[]>([])
const debounced = refDebounced(query, 250)
watch(debounced, async (q) => {
  found.value = q.trim() ? await useApi<Match[]>(`/users/lookup?search=${encodeURIComponent(q.trim())}`) : []
})
const matches = computed(() => found.value.filter(m => !m.squad_ids.includes(props.squadId)))

// squad_ids here are only the squads the caller may hand out; the server leaves the rest alone
const setAccess = (id: number, squadIDs: number[]) => useApi(`/users/${id}/access`, { method: 'PUT', body: { squad_ids: squadIDs } })

const { run: add } = useAsyncAction(async (m: Match) => {
  await setAccess(m.id, [...m.squad_ids, props.squadId])
  query.value = ''
  found.value = []
  await refresh()
  emit('changed')
}, 'User added.')

const { run: removeMember } = useAsyncAction(async (u: PanelUser) => {
  const mine = new Set((await useApi<Squad[]>('/squads')).map(s => s.id))
  await setAccess(u.id, u.squad_ids.filter(id => id !== props.squadId && mine.has(id)))
  await refresh()
  emit('changed')
}, 'User removed.')
</script>
