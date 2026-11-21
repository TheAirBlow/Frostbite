<template>
  <section class="surface p-4 sm:p-5">
    <div v-if="title || $slots.actions" class="mb-3 flex items-start justify-between gap-3">
      <div class="min-w-0 flex-1">
        <h3 class="text-base-content/70 text-sm font-semibold tracking-wide uppercase">{{ t(title) }}</h3>
        <p v-if="hint" class="text-base-content/60 text-xs">{{ t(hint) }}</p>
      </div>
      <slot name="actions" />
    </div>
    <slot />
  </section>
</template>

<script setup lang="ts">
defineProps<{ title?: string, hint?: string }>()
const { t } = useT()
</script>
