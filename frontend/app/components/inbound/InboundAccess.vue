<template>
  <div class="flex flex-col gap-3">
    <p class="text-base-content/60 text-sm">{{ $t('Users reach this inbound through squads. Tick the squads that should get it.') }}</p>
    <Skeleton v-if="!squads" :rows="3" :height="52" />
    <template v-else-if="squads.length">
      <label v-for="s in squads" :key="s.id" class="surface flex cursor-pointer items-center gap-3 p-3">
        <input type="checkbox" class="checkbox checkbox-primary" :checked="s.inbound_ids.includes(inboundId)" @change="toggle(s, ($event.target as HTMLInputElement).checked)">
        <div class="min-w-0 flex-1"><p class="font-medium">{{ s.name }}</p><p class="text-base-content/50 text-xs">{{ s.users }} user{{ s.users === 1 ? '' : 's' }} · {{ s.inbound_ids.length }} inbound{{ s.inbound_ids.length === 1 ? '' : 's' }}</p></div>
      </label>
    </template>
    <EmptyState v-else icon="fa6-solid:layer-group" :title="$t('No squads yet')" text="Create a squad first, then come back to put this inbound in it.">
      <NuxtLink to="/access" class="btn btn-primary btn-sm">{{ $t('Open squads') }}</NuxtLink>
    </EmptyState>
  </div>
</template>

<script setup lang="ts">
import type { Squad } from '~/types/api'

const props = defineProps<{ inboundId: number }>()
const { data: squads, refresh } = useAsyncData('squads', () => useApi<Squad[]>('/squads'))

const { run: toggle } = useAsyncAction(async (s: Squad, on: boolean) => {
  const ids = on ? [...s.inbound_ids, props.inboundId] : s.inbound_ids.filter(i => i !== props.inboundId)
  await useApi(`/squads/${s.id}`, { method: 'PUT', body: { name: s.name, note: s.note, inbound_ids: ids } })
  await refresh()
}, 'Updated.')
</script>
