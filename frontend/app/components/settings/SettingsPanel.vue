<template>
  <AppModal :title="$t('Settings')" max-width="max-w-5xl" height="sm:h-[85vh]" fullscreen @close="modal.close">
    <div class="flex h-full flex-col gap-4 sm:flex-row sm:gap-6">
      <div class="dropdown sm:hidden">
        <button tabindex="0" class="btn btn-sm w-full justify-between">{{ current.label }} <Icon name="fa6-solid:chevron-down" size="11" /></button>
        <ul tabindex="0" class="dropdown-content menu bg-base-200 rounded-box z-10 mt-1 w-full p-2 shadow"><li v-for="t in visible" :key="t.id"><button @click="select(t.id)"><Icon :name="t.icon" size="13" /> {{ t.label }}</button></li></ul>
      </div>
      <nav class="hidden w-48 shrink-0 flex-col gap-0.5 sm:flex">
        <button v-for="t in visible" :key="t.id" class="rounded-box flex items-center gap-2.5 px-3.5 py-2.5 text-left text-sm transition-colors" :class="tab === t.id ? 'bg-base-200 text-primary font-semibold' : 'text-base-content/70 hover:bg-base-200'" @click="select(t.id)">
          <Icon :name="t.icon" size="14" /> {{ t.label }}
        </button>
      </nav>
      <div class="min-w-0 flex-1">
        <Transition name="fade" mode="out-in">
          <KeepAlive>
            <SettingsAccountTab v-if="tab === 'account'" key="account" />
            <SettingsTokensTab v-else-if="tab === 'tokens'" key="tokens" />
            <SettingsAppearanceTab v-else-if="tab === 'appearance'" key="appearance" />
            <SettingsNotificationsTab v-else-if="tab === 'notifications'" key="notifications" />
            <SettingsAdminsTab v-else-if="tab === 'admins'" key="admins" />
            <SettingsBackupsTab v-else-if="tab === 'backups'" key="backups" />
            <SettingsAuditTab v-else-if="tab === 'audit'" key="audit" />
            <SettingsAboutTab v-else key="about" />
          </KeepAlive>
        </Transition>
      </div>
    </div>
  </AppModal>
</template>

<script setup lang="ts">
const modal = useDrawer()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const tabs = [
  { id: 'account', label: 'Account', icon: 'fa6-solid:user', owner: false },
  { id: 'tokens', label: 'API tokens', icon: 'fa6-solid:key', owner: false },
  { id: 'appearance', label: 'Appearance', icon: 'fa6-solid:palette', owner: false },
  { id: 'notifications', label: 'Notifications', icon: 'fa6-solid:bell', owner: false },
  { id: 'admins', label: 'Admins', icon: 'fa6-solid:user-shield', owner: true },
  { id: 'backups', label: 'Backups', icon: 'fa6-solid:box-archive', owner: true },
  { id: 'audit', label: 'Audit log', icon: 'fa6-solid:clock-rotate-left', owner: true },
  { id: 'about', label: 'About', icon: 'fa6-solid:circle-info', owner: false },
]
const staffOnly = ['notifications']
const visible = computed(() => tabs.filter(t => (!t.owner || auth.isOwner) && (!staffOnly.includes(t.id) || !auth.isReseller)))
const tab = computed(() => (route.query.tab as string | undefined) ?? 'account')
const current = computed(() => visible.value.find(t => t.id === tab.value) ?? visible.value[0]!)

function select(id: string) {
  router.replace({ query: { ...route.query, tab: id } })
}
</script>
