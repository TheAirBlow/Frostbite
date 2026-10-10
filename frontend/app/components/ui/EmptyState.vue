<template>
  <div class="flex flex-col items-center gap-3 px-6 py-14 text-center">
    <span class="bg-base-300/60 text-base-content/50 grid size-14 place-items-center rounded-2xl"><Icon :name="icon" size="24" /></span>
    <div>
      <p class="font-display text-lg font-semibold">{{ t(title) }}</p>
      <p v-if="text" class="text-base-content/60 mx-auto mt-1 max-w-md text-sm">{{ t(text) }}</p>
    </div>
    <slot />
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ icon?: string, title: string, text?: string }>(), { icon: 'fa6-solid:snowflake', text: '' })
const { t } = useT()
</script>
