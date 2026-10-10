<template>
  <SettingsPanel v-if="panel === 'settings'" />
  <UserCreateModal v-else-if="panel === 'user-create'" />
  <UserBatchModal v-else-if="panel === 'user-batch'" />
  <UserImportModal v-else-if="panel === 'user-import'" />
  <BridgeWizard v-else-if="panel === 'bridge'" />
  <CommandPalette v-else-if="panel === 'palette'" />

  <AppDrawer :open="drawerOpen" :title="meta.title" :subtitle="meta.subtitle" :width="meta.width" @close="close" @closed="onClosed">
    <template v-if="shownKind === 'user' && shownId" #tabs>
      <UserDrawerTabs v-model="userTab" />
    </template>
    <UserDrawer v-if="shownKind === 'user'" :id="shownId!" :key="`u${shownId}`" v-model:tab="userTab" @title="setMeta" @deleted="close" />
    <NodeDrawer v-else-if="shownKind === 'node'" :id="shownId" :key="`n${shownId ?? 'new'}`" @title="setMeta" @done="close" />
    <DaemonDrawer v-else-if="shownKind === 'daemon'" :id="shownId!" :key="`d${shownId}`" @title="setMeta" @done="close" />
    <InboundDrawer v-else-if="shownKind === 'inbound'" :id="shownId" :key="`i${shownId ?? 'new'}${route.query.daemon ?? ''}`" @title="setMeta" @done="close" />
    <OutboundDrawer v-else-if="shownKind === 'outbound'" :id="shownId" :key="`o${shownId ?? 'new'}${route.query.daemon ?? ''}`" @title="setMeta" @done="close" />
    <RuleDrawer v-else-if="shownKind === 'rule'" :id="shownId" :key="`r${shownId ?? 'new'}`" @title="setMeta" @done="close" />
    <SquadDrawer v-else-if="shownKind === 'squad'" :id="shownId" :key="`s${shownId ?? 'new'}`" @title="setMeta" @done="close" />
    <PlanDrawer v-else-if="shownKind === 'plan'" :id="shownId" :key="`p${shownId ?? 'new'}`" @title="setMeta" @done="close" />
  </AppDrawer>
</template>

<script setup lang="ts">
import type { SideDrawerKind } from '~/composables/useSideDrawer'

const route = useRoute()
const modal = useDrawer()
const side = useSideDrawer()

const panel = modal.current
const drawerOpen = computed(() => side.isOpen.value)

// keep the content alive until the closing transition ends so it does not vanish mid slide
const shownKind = ref<SideDrawerKind | null>(side.kind.value)
const shownId = ref<number | null>(side.id.value)
watch([side.kind, side.id], ([k, i]) => {
  if (k) {
    shownKind.value = k
    shownId.value = i
  }
})

const meta = reactive({ title: '', subtitle: '', width: 'max-w-xl' })
function setMeta(m: { title: string, subtitle?: string, width?: string }) {
  meta.title = m.title
  meta.subtitle = m.subtitle ?? ''
  meta.width = m.width ?? 'max-w-xl'
}

const userTab = ref('overview')
watch(() => side.id.value, () => (userTab.value = 'overview'))

function close() {
  side.close()
}

function onClosed() {
  if (!side.isOpen.value) {
    shownKind.value = null
    shownId.value = null
    meta.title = ''
    meta.subtitle = ''
  }
}
</script>
