<template>
  <label class="flex cursor-pointer items-start justify-between gap-4 py-1.5">
    <span class="min-w-0">
      <span class="block text-sm">{{ t(label) }}</span>
      <span v-if="hint" class="text-base-content/60 block text-xs">{{ t(hint) }}</span>
    </span>
    <input v-model="model" type="checkbox" class="toggle toggle-primary mt-0.5 shrink-0">
  </label>
</template>

<script setup lang="ts">
defineProps<{ label: string, hint?: string }>()
const { t } = useT()
const model = defineModel<boolean>({ default: false })
</script>
