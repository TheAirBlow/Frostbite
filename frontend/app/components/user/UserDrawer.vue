<template>
  <Skeleton v-if="!user" :rows="5" :height="64" />
  <div v-else>
    <UserOverview v-if="tab === 'overview'" :user="user" @changed="reload" @deleted="emit('deleted')" @tab="tab = $event" />
    <UserSettings v-else-if="tab === 'settings'" :user="user" @changed="reload" />
    <UserLinks v-else-if="tab === 'links'" :user="user" />
    <UserTraffic v-else-if="tab === 'traffic'" :user="user" />
    <UserDevices v-else-if="tab === 'devices'" :user="user" />
  </div>
</template>

<script setup lang="ts">
import type { PanelUser } from '~/types/api'

const props = defineProps<{ id: number }>()
const emit = defineEmits<{ title: [m: { title: string, subtitle?: string, width?: string }], deleted: [] }>()
const tab = defineModel<string>('tab', { default: 'overview' })

const { data: user, refresh } = useAsyncData(`user-${props.id}`, () => useApi<PanelUser>(`/users/${props.id}`))

watch(user, (u) => {
  if (u) emit('title', { title: u.username, subtitle: u.note || `Created ${formatDate(u.created_at)}`, width: 'max-w-2xl' })
}, { immediate: true })

async function reload() {
  await refresh()
  await refreshNuxtData('users')
}

usePolling(async () => {
  if (!document.hidden) await refresh()
  return null
}, 15000)
</script>
