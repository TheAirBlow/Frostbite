<template>
  <AppModal :title="$t('Settings')" max-width="max-w-5xl" height="sm:h-[85vh]" fullscreen @close="modal.close">
    <div class="flex flex-col gap-4 sm:h-full sm:flex-row sm:gap-6">
      <nav ref="strip" class="bg-base-100 border-base-300 sticky -top-5 z-10 -mx-5 -mt-5 flex shrink-0 gap-1 overflow-x-auto [scrollbar-width:none] border-b px-5 py-2 sm:hidden">
        <button v-for="t in visible" :key="t.id" class="btn btn-sm shrink-0 gap-1.5" :data-active="tab === t.id || undefined" :class="tab === t.id ? 'btn-soft btn-primary' : 'btn-ghost text-base-content/70'" @click="select(t.id)">
          <Icon :name="t.icon" size="12" /> {{ t.label }}
        </button>
      </nav>
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
const visible = computed(() => tabs.filter(t => (!t.owner || auth.isOwner) && (!staffOnly.includes(t.id) || (!auth.isReseller && !auth.isNodeAdmin))))
const tab = computed(() => (route.query.tab as string | undefined) ?? 'account')

const strip = useTemplateRef('strip')
watch(tab, () => nextTick(() => strip.value?.querySelector('[data-active]')?.scrollIntoView({ block: 'nearest', inline: 'center' })), { immediate: true })

function select(id: string) {
  router.replace({ query: { ...route.query, tab: id } })
}
</script>
