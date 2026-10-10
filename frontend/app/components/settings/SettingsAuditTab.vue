<template>
  <div class="flex flex-col gap-3">
    <p class="text-base-content/60 text-sm">{{ $t('Every change made through the panel, newest first.') }}</p>
    <Skeleton v-if="pending" :rows="6" :height="40" />
    <div v-else-if="entries.length" class="surface divide-base-300 divide-y overflow-hidden">
      <div v-for="e in entries" :key="e.id" class="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-4 py-2.5 text-sm">
        <span class="text-base-content/50 w-36 shrink-0 text-xs">{{ formatDateTime(e.created_at) }}</span>
        <span class="font-medium">{{ e.admin_name }}</span>
        <span class="badge badge-sm badge-ghost font-mono">{{ e.action }}</span>
        <span class="text-base-content/70 min-w-0 flex-1 truncate">{{ e.target }}</span>
      </div>
    </div>
    <EmptyState v-else icon="fa6-solid:clock-rotate-left" :title="$t('Nothing yet')" />
    <button v-if="entries.length >= limit" class="btn btn-sm self-center" @click="limit += 50">{{ $t('Load more') }}</button>
  </div>
</template>

<script setup lang="ts">
import type { AuditEntry } from '~/types/api'

const limit = ref(50)
const { data, pending } = useAsyncData('audit', () => useApi<AuditEntry[]>('/audit', { query: { limit: limit.value } }), { watch: [limit] })
const entries = computed(() => data.value ?? [])
</script>
