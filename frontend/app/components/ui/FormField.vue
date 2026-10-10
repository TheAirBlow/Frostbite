<template>
  <fieldset class="fieldset min-w-0">
    <legend class="fieldset-legend flex items-center gap-2">
      {{ t(label) }}
      <span v-if="badge" class="badge badge-xs badge-ghost">{{ t(badge) }}</span>
    </legend>
    <slot />
    <p v-if="hint" class="text-base-content/60 text-xs">{{ t(hint) }}</p>
  </fieldset>
</template>

<script setup lang="ts">
defineProps<{ label: string, hint?: string, badge?: string }>()
const { t } = useT()
</script>
