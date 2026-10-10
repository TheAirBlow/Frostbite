<template>
  <div>
    <textarea
      v-model="text"
      class="textarea textarea-sm w-full font-mono text-xs leading-relaxed"
      :class="{ 'textarea-error': error }"
      :rows="rows"
      spellcheck="false"
      :placeholder="placeholder"
      @input="parse"
    />
    <p v-if="error" class="text-error mt-1 text-xs">{{ error }}</p>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ rows?: number, placeholder?: string }>(), { rows: 6, placeholder: '{ }' })
const model = defineModel<Record<string, unknown> | null>({ default: null })

const text = ref(model.value ? JSON.stringify(model.value, null, 2) : '')
const error = ref('')

function parse() {
  const raw = text.value.trim()
  if (!raw) {
    error.value = ''
    model.value = null
    return
  }
  try {
    const v = JSON.parse(raw)
    if (typeof v !== 'object' || Array.isArray(v) || v === null) throw new Error('must be a json object')
    error.value = ''
    model.value = v
  }
  catch (e) {
    error.value = (e as Error).message
  }
}

watch(model, (v) => {
  // follow outside changes, but never fight what is being typed
  if (error.value) return
  const next = v ? JSON.stringify(v, null, 2) : ''
  if (next !== text.value.trim() && JSON.stringify(safe(text.value)) !== JSON.stringify(v)) text.value = next
})

function safe(s: string) {
  try {
    return s.trim() ? JSON.parse(s) : null
  }
  catch {
    return undefined
  }
}
</script>
