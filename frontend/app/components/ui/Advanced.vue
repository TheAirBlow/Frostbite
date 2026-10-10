<template>
  <!-- daisyUI collapse on a native <details>, so a field inside stays in the page and can be opened when it has an error -->
  <details class="collapse collapse-arrow border-base-300 rounded-box border border-dashed" :open="prefs.advanced || undefined">
    <summary class="collapse-title text-base-content/60 flex min-h-0 items-center gap-2 py-2.5 text-xs font-semibold tracking-wide uppercase">
      <Icon name="fa6-solid:sliders" size="11" /> {{ t(title) }}
    </summary>
    <div class="collapse-content flex flex-col gap-3 pb-3">
      <slot />
    </div>
  </details>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ title?: string }>(), { title: 'Advanced' })
const prefs = usePreferencesStore()
const { t } = useT()
</script>
