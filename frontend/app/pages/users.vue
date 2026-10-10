<template>
  <div>
    <PageHeader :title="t('users.title')" :subtitle="page ? t('users.total', { n: page.total }) : ' '">
      <button class="btn btn-ghost btn-sm" @click="drawer.open('user-import')"><Icon name="fa6-solid:file-import" size="13" /> {{ t('users.import') }}</button>
      <button class="btn btn-ghost btn-sm" @click="drawer.open('user-batch')"><Icon name="fa6-solid:users-line" size="13" /> {{ t('users.batch') }}</button>
      <button class="btn btn-primary btn-sm" @click="drawer.open('user-create')"><Icon name="fa6-solid:user-plus" size="13" /> {{ t('users.new') }}</button>
    </PageHeader>

    <div v-if="quota && (quota.user_quota || quota.traffic_quota)" class="surface mb-3 flex flex-wrap items-center gap-x-8 gap-y-2 px-4 py-3">
      <div v-if="quota.user_quota" class="min-w-40 flex-1"><p class="text-base-content/60 text-xs">{{ $t('Users') }}</p><p class="text-sm font-medium">{{ quota.users }} of {{ quota.user_quota }}</p><progress class="progress progress-primary h-1.5 w-full" :value="quota.users" :max="quota.user_quota" /></div>
      <div v-if="quota.traffic_quota" class="min-w-40 flex-1"><p class="text-base-content/60 text-xs">{{ $t('Traffic handed out') }}</p><p class="text-sm font-medium">{{ formatBytes(quota.traffic_allocated) }} of {{ formatBytes(quota.traffic_quota) }}</p><progress class="progress progress-secondary h-1.5 w-full" :value="quota.traffic_allocated" :max="quota.traffic_quota" /></div>
    </div>

    <div class="bg-base-100/90 sticky top-0 z-20 -mx-4 flex flex-col gap-3 px-4 pt-2 pb-3 backdrop-blur sm:-mx-6 sm:px-6">
      <div class="flex flex-wrap items-center gap-2">
        <label class="input input-sm flex min-w-52 flex-1 items-center gap-2 sm:max-w-sm">
          <Icon name="fa6-solid:magnifying-glass" size="12" class="opacity-50" />
          <input v-model="search" type="search" :placeholder="t('users.search')" class="grow">
        </label>
        <select v-if="squads?.length" v-model="squad" class="select select-sm w-auto">
          <option value="">{{ $t('All squads') }}</option>
          <option v-for="s in squads" :key="s.id" :value="s.id">{{ s.name }}</option>
        </select>
        <select v-model="sort" class="select select-sm w-auto">
          <option value="">{{ $t('Newest') }}</option>
          <option value="used">{{ $t('Most traffic') }}</option>
          <option value="expire">{{ $t('Expiring soon') }}</option>
          <option value="online">{{ $t('Recently online') }}</option>
          <option value="name">{{ $t('Name') }}</option>
        </select>
        <input v-model="tag" class="input input-sm w-28" :placeholder="$t('tag')">
      </div>
      <div class="flex flex-wrap gap-1.5">
        <button v-for="s in statusChips" :key="s.value" class="btn btn-xs rounded-full" :class="status === s.value ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="status = s.value">
          {{ s.value ? t(`status.${s.value}`) : t('users.all') }}
        </button>
      </div>
    </div>

    <div class="surface overflow-hidden">
      <div class="text-base-content/50 border-base-300 hidden items-center gap-3 border-b px-4 py-2.5 text-xs font-medium tracking-wide uppercase lg:grid lg:grid-cols-[auto_minmax(0,2fr)_6rem_minmax(0,1.4fr)_9rem_7rem_auto]">
        <input type="checkbox" class="checkbox checkbox-xs" :checked="allSelected" @change="toggleAll">
        <span>{{ t('users.colUser') }}</span><span>{{ t('users.colStatus') }}</span><span>{{ t('users.colUsage') }}</span><span>{{ t('users.colExpires') }}</span><span>{{ t('users.colSeen') }}</span><span class="w-20" />
      </div>

      <Skeleton v-if="shown" :rows="8" :height="58" class="p-3" />
      <template v-else-if="page?.items.length">
        <div
          v-for="u in page.items"
          :key="u.id"
          class="border-base-300 hover:bg-base-300/30 grid cursor-pointer grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2 border-b px-4 py-3 last:border-b-0 lg:grid-cols-[auto_minmax(0,2fr)_6rem_minmax(0,1.4fr)_9rem_7rem_auto]"
          :class="{ 'bg-primary/5': selected.has(u.id) }"
          @click="side.open('user', u.id)"
        >
          <input type="checkbox" class="checkbox checkbox-xs" :checked="selected.has(u.id)" @click.stop @change="toggle(u.id)">
          <div class="min-w-0">
            <p class="flex items-center gap-2 font-medium">
              <Dot :tone="u.online ? 'success' : 'muted'" :pulse="u.online" />
              <span class="truncate">{{ u.username }}</span>
            </p>
            <p class="text-base-content/50 flex flex-wrap items-center gap-x-2 text-xs">
              <span v-for="label in u.tags.slice(0, 3)" :key="label" class="badge badge-xs badge-ghost">{{ label }}</span>
              <span v-if="u.note" class="max-w-52 truncate">{{ u.note }}</span>
            </p>
          </div>
          <div class="justify-self-end lg:justify-self-start"><StatusBadge :status="u.status" /></div>
          <div class="col-span-3 lg:col-span-1"><UsageBar :used="u.traffic_used" :limit="u.traffic_limit" /></div>
          <p class="hidden text-sm lg:block" :class="expiryClass(u)">
            {{ u.expire_at ? formatDate(u.expire_at) : u.status === 'on_hold' ? `${u.on_hold_days || '∞'}d after first use` : t('users.never') }}
            <span v-if="u.expire_at" class="text-base-content/50 block text-xs">{{ expiryHint(u) }}</span>
          </p>
          <p class="text-base-content/60 hidden text-xs lg:block">{{ u.online ? t('users.onlineNow') : formatRelative(u.online_at) }}</p>
          <div class="flex items-center justify-end gap-0.5" @click.stop>
            <CopyButton :value="u.sub_url" label="Copy subscription link" />
            <button class="btn btn-ghost btn-xs btn-square" :title="$t('QR code')" @click="qr = u"><Icon name="fa6-solid:qrcode" size="13" /></button>
          </div>
        </div>
      </template>
      <EmptyState v-else icon="fa6-solid:users" :title="filtered ? 'Nobody matches those filters' : 'No users yet'" :text="filtered ? 'Try clearing the search or the status filter.' : 'Create the first one and share their link.'">
        <button v-if="!filtered" class="btn btn-primary btn-sm" @click="drawer.open('user-create')">{{ $t('New user') }}</button>
        <button v-else class="btn btn-sm" @click="clearFilters">{{ $t('Clear filters') }}</button>
      </EmptyState>
    </div>

    <div v-if="page && page.total > pageSize" class="mt-3 flex items-center justify-between text-sm">
      <span class="text-base-content/60">{{ offset + 1 }}–{{ Math.min(offset + pageSize, page.total) }} of {{ page.total }}</span>
      <div class="join">
        <button class="btn btn-sm join-item" :disabled="offset === 0" @click="offset = Math.max(0, offset - pageSize)"><Icon name="fa6-solid:chevron-left" size="11" /></button>
        <button class="btn btn-sm join-item" :disabled="offset + pageSize >= page.total" @click="offset += pageSize"><Icon name="fa6-solid:chevron-right" size="11" /></button>
      </div>
    </div>

    <BulkBar v-if="selected.size" :ids="[...selected]" :squads="squads ?? []" @clear="selected = new Set()" @done="onBulkDone" />

    <AppModal v-if="qr" :title="qr.username" subtitle="Scan with any client" max-width="max-w-sm" @close="qr = null">
      <div class="flex flex-col items-center gap-3">
        <QrCode :value="qr.sub_url" :size="240" />
        <p class="text-base-content/60 max-w-full text-center font-mono text-xs break-all">{{ qr.sub_url }}</p>
        <CopyButton :value="qr.sub_url" />
      </div>
    </AppModal>
  </div>
</template>

<script setup lang="ts">
import type { PanelUser, Quota, Squad, UserPage } from '~/types/api'

useHead({ title: 'Users' })

const drawer = useDrawer()
const { t } = useT()
const side = useSideDrawer()
const prefs = usePreferencesStore()

const search = ref('')
const debounced = refDebounced(search, 300)
const status = ref('')
const squad = ref<number | ''>('')
const tag = ref('')
const sort = ref(prefs.usersSort)
const offset = ref(0)
const pageSize = computed(() => prefs.usersPageSize)
const selected = ref(new Set<number>())
const qr = ref<PanelUser | null>(null)

watch(sort, v => (prefs.usersSort = v))
watch([debounced, status, squad, tag, sort], () => {
  offset.value = 0
  selected.value = new Set()
})

const { data: page, pending, refresh } = useAsyncData(
  'users',
  () => useApi<UserPage>('/users', {
    query: { search: debounced.value, status: status.value, squad: squad.value, tag: tag.value, sort: sort.value, limit: pageSize.value, offset: offset.value },
  }),
  { watch: [debounced, status, squad, tag, sort, offset] },
)
const { data: squads } = useAsyncData('squads', () => useApi<Squad[]>('/squads'))
const { data: quota } = useAsyncData('quota', () => useApi<Quota>('/quota'), { server: false })
const shown = useDelayedPending(computed(() => pending.value && !page.value))

// the list is also live: online dots and usage move without a reload
usePolling(async () => {
  if (!document.hidden) await refresh()
  return null
}, 20000)

const statusChips = [
  { value: '', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'on_hold', label: 'On hold' },
  { value: 'limited', label: 'Limited' },
  { value: 'expired', label: 'Expired' },
  { value: 'disabled', label: 'Disabled' },
]

const filtered = computed(() => !!(debounced.value || status.value || squad.value || tag.value))
function clearFilters() {
  search.value = ''
  status.value = ''
  squad.value = ''
  tag.value = ''
}

const allSelected = computed(() => !!page.value?.items.length && page.value.items.every(u => selected.value.has(u.id)))
function toggle(id: number) {
  const next = new Set(selected.value)
  if (!next.delete(id)) next.add(id)
  selected.value = next
}
function toggleAll() {
  selected.value = allSelected.value ? new Set() : new Set(page.value?.items.map(u => u.id))
}
function onBulkDone() {
  selected.value = new Set()
  refresh()
}

function expiryClass(u: PanelUser) {
  const d = daysLeft(u.expire_at)
  if (d === null) return ''
  return d < 0 ? 'text-error' : d <= 3 ? 'text-warning' : ''
}
function expiryHint(u: PanelUser) {
  const d = daysLeft(u.expire_at)!
  if (d < 0) return `${-d}d ago`
  return d === 0 ? 'today' : `in ${d}d`
}
</script>
