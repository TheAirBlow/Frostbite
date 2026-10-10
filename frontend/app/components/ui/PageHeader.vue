<template>
  <div class="mb-5 flex flex-wrap items-end justify-between gap-3">
    <div class="min-w-0">
      <h1 class="font-display text-3xl font-semibold tracking-tight">{{ t(title) }}</h1>
      <p v-if="subtitle" class="text-base-content/60 mt-0.5 text-sm">{{ t(subtitle) }}</p>
    </div>
    <div class="flex flex-wrap items-center gap-2">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ title: string, subtitle?: string }>()
const { t } = useT()
</script>
