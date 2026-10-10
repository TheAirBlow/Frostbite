<template>
  <div class="group relative flex">
    <slot />
    <div
      class="bg-base-300 text-base-content pointer-events-none absolute top-1/2 left-full z-50 ml-2 flex -translate-y-1/2 items-center gap-1.5 rounded-lg px-2 py-1 text-xs whitespace-nowrap opacity-0 shadow transition-opacity group-hover:opacity-100"
    >
      {{ label }}
      <kbd v-if="kbd" class="kbd kbd-sm">{{ kbd }}</kbd>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ label: string, kbd?: string }>()
</script>
