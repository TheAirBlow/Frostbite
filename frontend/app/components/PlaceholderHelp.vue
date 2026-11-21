<template>
  <details class="text-base-content/60 text-xs">
    <summary class="cursor-pointer select-none">{{ t(title) }}</summary>
    <dl class="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
      <template v-for="name in names" :key="name">
        <dt><code class="bg-base-300/60 rounded px-1 font-mono">{{ braced(name) }}</code></dt>
        <dd>{{ t(placeholderHints[name] ?? '') }}</dd>
      </template>
    </dl>
    <p class="mt-2">
      {{ t('Add :upper or :lower to change the case, like {protocol:upper}. Unknown placeholders are left as written.') }}
    </p>
  </details>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ names: string[], title?: string }>(), { title: 'Placeholders' })
const { t } = useT()
const braced = (name: string) => `{${name}}`
</script>
