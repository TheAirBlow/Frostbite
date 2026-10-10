<template>
  <AppModal title="" max-width="max-w-xl" hide-close @close="modal.close">
    <template #header>
      <label class="input w-full">
        <Icon name="fa6-solid:magnifying-glass" size="13" class="opacity-50" />
        <input ref="input" v-model="query" :placeholder="$t('Jump to a page, a user, a node…')" class="grow" @keydown.down.prevent="move(1)" @keydown.up.prevent="move(-1)" @keydown.enter.prevent="go()">
        <kbd class="kbd kbd-sm">Esc</kbd>
      </label>
    </template>
    <ul class="-m-2 flex max-h-[50vh] flex-col overflow-y-auto">
      <li v-for="(r, i) in results" :key="r.key">
        <button class="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left" :class="i === active ? 'bg-primary/15 text-primary' : 'hover:bg-base-200'" @mouseenter="active = i" @click="active = i; go()">
          <Icon :name="r.icon" size="14" class="w-4 opacity-70" />
          <span class="min-w-0 flex-1 truncate">{{ r.label }}</span>
          <span class="text-base-content/50 text-xs">{{ r.hint }}</span>
        </button>
      </li>
      <li v-if="!results.length" class="text-base-content/50 px-3 py-6 text-center text-sm">{{ $t('No match.') }}</li>
    </ul>
  </AppModal>
</template>

<script setup lang="ts">
import type { PanelNode, UserPage } from '~/types/api'

const modal = useDrawer()
const side = useSideDrawer()
const auth = useAuthStore()
const input = useTemplateRef('input')
const query = ref('')
const debounced = refDebounced(query, 200)
const active = ref(0)

interface Result { key: string, label: string, hint: string, icon: string, run: () => void }

const pages: Result[] = [
  ['Dashboard', '/', 'fa6-solid:chart-line'], ['Users', '/users', 'fa6-solid:users'], ['Nodes', '/nodes', 'fa6-solid:server'], ['Inbounds', '/inbounds', 'fa6-solid:plug'],
  ['Routing', '/routing', 'fa6-solid:route'], ['Bridges', '/bridges', 'fa6-solid:bridge'], ['Squads & plans', '/access', 'fa6-solid:layer-group'], ['Subscriptions', '/subscriptions', 'fa6-solid:rss'],
].map(([label, to, icon]) => ({ key: `p${to}`, label: label!, hint: 'page', icon: icon!, run: () => navigateTo(to!) }))

const actions: Result[] = [
  { key: 'a-user', label: 'New user', hint: 'action', icon: 'fa6-solid:user-plus', run: () => modal.open('user-create') },
  { key: 'a-node', label: 'Add a node', hint: 'action', icon: 'fa6-solid:server', run: () => side.open('node') },
  { key: 'a-bridge', label: 'New bridge', hint: 'action', icon: 'fa6-solid:bridge', run: () => modal.open('bridge') },
  { key: 'a-settings', label: 'Settings', hint: 'action', icon: 'fa6-solid:gear', run: () => modal.open('settings') },
]

const { data: nodes } = useAsyncData('nodes', () => useApi<PanelNode[]>('/nodes'), { default: () => [] })
const users = ref<Result[]>([])
watch(debounced, async (q) => {
  users.value = !q ? [] : (await useApi<UserPage>('/users', { query: { search: q, limit: 6 } })).items.map(u => ({
    key: `u${u.id}`, label: u.username, hint: u.status, icon: 'fa6-solid:user', run: async () => {
      await navigateTo('/users')
      side.open('user', u.id)
    },
  }))
})

const results = computed(() => {
  const q = query.value.trim().toLowerCase()
  const nodeResults: Result[] = nodes.value.map(n => ({ key: `n${n.id}`, label: n.name, hint: n.address, icon: 'fa6-solid:server', run: async () => {
      await navigateTo('/nodes')
      side.open('node', n.id)
    } }))
  const base = auth.isReseller ? actions.slice(0, 1) : [...pages, ...actions, ...nodeResults]
  const hits = q ? base.filter(r => r.label.toLowerCase().includes(q) || r.hint.toLowerCase().includes(q)) : base.slice(0, 12)
  return [...hits, ...users.value].slice(0, 14)
})

watch(results, () => (active.value = 0))
onMounted(() => nextTick(() => input.value?.focus()))

function move(d: number) {
  active.value = (active.value + d + results.value.length) % Math.max(results.value.length, 1)
}

function go() {
  const r = results.value[active.value]
  if (!r) return
  modal.close()
  setTimeout(r.run, 60)
}
</script>
