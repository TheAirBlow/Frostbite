<template>
  <div class="bg-base-100 border-base-content/20 focus-within:border-primary flex min-h-9 flex-wrap items-center gap-1.5 rounded-field border px-2 py-1.5" @click="input?.focus()">
    <span v-for="(c, i) in model" :key="c + i" class="badge badge-primary badge-soft gap-1">
      {{ c }}
      <button type="button" class="opacity-60 hover:opacity-100" :aria-label="`Remove ${c}`" @click.stop="remove(i)">
        <Icon name="fa6-solid:xmark" size="10" />
      </button>
    </span>
    <input
      ref="input"
      v-model="draft"
      class="min-w-24 flex-1 bg-transparent text-sm"
      :placeholder="model.length ? '' : placeholder"
      @keydown.enter.prevent="commit"
      @keydown.,.prevent="commit"
      @keydown.backspace="onBackspace"
      @blur="commit"
      @paste="onPaste"
    >
  </div>
</template>

<script setup lang="ts">
defineProps<{ placeholder?: string }>()
const model = defineModel<string[]>({ default: () => [] })
const input = useTemplateRef('input')
const draft = ref('')

function commit() {
  const parts = draft.value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean)
  draft.value = ''
  if (!parts.length) return
  model.value = [...new Set([...model.value, ...parts])]
}

function remove(i: number) {
  model.value = model.value.filter((_, idx) => idx !== i)
}

function onBackspace() {
  if (!draft.value && model.value.length) remove(model.value.length - 1)
}

function onPaste(e: ClipboardEvent) {
  const text = e.clipboardData?.getData('text')
  if (text && /[\s,]/.test(text)) {
    e.preventDefault()
    draft.value = text
    commit()
  }
}
</script>
