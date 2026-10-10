<template>
  <div class="surface relative overflow-hidden p-4">
    <div class="flex items-start justify-between gap-2">
      <p class="text-base-content/60 text-xs font-medium tracking-wide uppercase">{{ t(label) }}</p>
      <span v-if="icon" class="grid size-8 place-items-center rounded-xl" :class="tone"><Icon :name="icon" size="15" /></span>
    </div>
    <p class="font-display mt-2 text-3xl leading-none font-semibold tracking-tight">{{ value }}</p>
    <p v-if="hint" class="text-base-content/50 mt-1.5 text-xs">{{ t(hint) }}</p>
    <slot />
  </div>
</template>

<script setup lang="ts">
const { t } = useT()
withDefaults(defineProps<{ label: string, value: string | number, hint?: string, icon?: string, tone?: string }>(), {
  tone: 'bg-primary/15 text-primary',
  hint: '',
  icon: '',
})
</script>
