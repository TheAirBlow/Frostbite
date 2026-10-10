<template>
  <div v-if="prefs.advanced || open || forced" class="border-base-300 rounded-box border border-dashed p-3">
    <div class="text-base-content/60 mb-2 flex items-center gap-2 text-xs font-semibold tracking-wide uppercase">
      <Icon name="fa6-solid:sliders" size="11" /> {{ t(title) }}
    </div>
    <slot />
  </div>
  <button v-else type="button" class="btn btn-ghost btn-sm text-base-content/60 self-start" @click="open = true">
    <Icon name="fa6-solid:chevron-down" size="11" /> {{ t(title) }}
  </button>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ title?: string, forced?: boolean }>(), { title: 'Advanced' })
const prefs = usePreferencesStore()
const { t } = useT()
const open = ref(false)
</script>
