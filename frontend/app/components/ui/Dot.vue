<template>
  <span class="relative inline-flex size-2.5">
    <span v-if="pulse" class="absolute inline-flex size-full animate-ping rounded-full opacity-60" :class="color" />
    <span class="relative inline-flex size-2.5 rounded-full" :class="color" />
  </span>
</template>

<script setup lang="ts">
const props = defineProps<{ tone: 'success' | 'warning' | 'error' | 'muted', pulse?: boolean }>()
const color = computed(() => ({ success: 'bg-success', warning: 'bg-warning', error: 'bg-error', muted: 'bg-base-content/30' })[props.tone])
</script>
