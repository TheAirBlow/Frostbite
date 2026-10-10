<template>
  <div class="min-w-0">
    <div class="bg-base-300 h-1.5 w-full overflow-hidden rounded-full">
      <div class="h-full rounded-full transition-all" :class="color" :style="{ width: unlimited ? '100%' : `${pct}%`, opacity: unlimited ? 0.25 : 1 }" />
    </div>
    <p v-if="!compact" class="text-base-content/60 mt-1 text-xs">
      {{ formatBytes(used) }}<template v-if="!unlimited"> / {{ formatBytes(limit) }}</template><template v-else> {{ $t('· unlimited') }}</template>
    </p>
  </div>
</template>

<script setup lang="ts">
const props = defineProps<{ used: number, limit: number, compact?: boolean }>()
const unlimited = computed(() => !props.limit)
const pct = computed(() => percent(props.used, props.limit))
const color = computed(() => (pct.value >= 95 ? 'bg-error' : pct.value >= 80 ? 'bg-warning' : 'bg-primary'))
</script>
