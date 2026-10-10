<template>
  <div class="flex flex-col gap-3">
    <p class="text-base-content/60 text-sm">
      {{ $t('Apps like Happ and Hiddify send a device id when they fetch the subscription.') }}
      <template v-if="user.device_limit">This user may use {{ user.device_limit }} of them.</template>
      <template v-else>{{ $t('There is no device limit set, so they are only listed here.') }}</template>
    </p>
    <Skeleton v-if="pending" :rows="3" />
    <div v-else-if="data?.length" class="flex flex-col gap-2">
      <div v-for="d in data" :key="d.id" class="surface flex items-center gap-3 p-3">
        <Icon :name="icon(d.platform)" size="20" class="text-base-content/60" />
        <div class="min-w-0 flex-1">
          <p class="truncate font-medium">{{ d.model || d.platform || 'Unknown device' }}</p>
          <p class="text-base-content/50 truncate text-xs">{{ [d.platform, d.os_version].filter(Boolean).join(' ') }} · seen {{ formatRelative(d.last_seen) }}</p>
          <p class="text-base-content/40 truncate font-mono text-[11px]">{{ d.hwid }}</p>
        </div>
        <ConfirmButton class="btn btn-ghost btn-xs text-error" confirm-label="Forget?" @confirmed="remove(d.id)"><Icon name="fa6-solid:trash" size="12" /></ConfirmButton>
      </div>
    </div>
    <EmptyState v-else icon="fa6-solid:mobile-screen" :title="$t('No devices seen')" text="They show up after the first subscription fetch from a client that sends a device id." />
  </div>
</template>

<script setup lang="ts">
import type { PanelUser, UserDevice } from '~/types/api'

const props = defineProps<{ user: PanelUser }>()
const { data, pending, refresh } = useAsyncData(`user-devices-${props.user.id}`, () => useApi<UserDevice[]>(`/users/${props.user.id}/devices`))

function icon(platform: string) {
  const p = platform.toLowerCase()
  if (p.includes('ios') || p.includes('android')) return 'fa6-solid:mobile-screen'
  if (p.includes('mac') || p.includes('windows') || p.includes('linux')) return 'fa6-solid:laptop'
  return 'fa6-solid:microchip'
}

const { run: remove } = useAsyncAction(async (id: number) => {
  await useApi(`/users/${props.user.id}/devices/${id}`, { method: 'DELETE' })
  await refresh()
}, 'Device forgotten.')
</script>
