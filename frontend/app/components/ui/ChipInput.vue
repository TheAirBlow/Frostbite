<template>
  <div>
    <!-- a div, not a label: a label would click its first button, which is a chip's remove button -->
    <div class="input h-auto min-h-10 w-full flex-wrap gap-1.5 py-1.5" @click="input?.focus()">
      <span v-for="(c, i) in model" :key="c + i" class="badge badge-primary badge-soft gap-1">
        {{ c }}
        <button type="button" class="opacity-60 hover:opacity-100" :aria-label="`${$t('Remove')} ${c}`" @click.stop="remove(i)">
          <Icon name="fa6-solid:xmark" size="10" />
        </button>
      </span>
      <input
        ref="input"
        v-model="draft"
        class="min-w-24 flex-1"
        :placeholder="model.length ? '' : placeholder"
        :aria-label="placeholder"
        @keydown.enter.prevent="commit"
        @keydown.,.prevent="commit"
        @keydown.backspace="onBackspace"
        @input="rejected = ''"
        @blur="commit"
        @paste="onPaste"
      >
    </div>
    <p v-if="rejected" class="text-error mt-1 text-xs" role="alert">{{ $t(rejected) }}</p>
  </div>
</template>

<script setup lang="ts">
// `check` vets each entry before it becomes a chip: return a message to refuse it, nothing to accept.
const props = defineProps<{ placeholder?: string, check?: (v: string) => string | undefined, spaces?: boolean }>()
const model = defineModel<string[]>({ default: () => [] })
const input = useTemplateRef('input')
const draft = ref('')
const rejected = ref('')

function commit() {
  const parts = draft.value.split(props.spaces ? /,/ : /[\s,]+/).map(s => s.trim()).filter(Boolean)
  if (!parts.length) return
  const accepted: string[] = []
  const refused: string[] = []
  for (const p of parts) {
    const why = props.check?.(p)
    if (why) refused.push(`${p}: ${why}`)
    else accepted.push(p)
  }
  if (accepted.length) model.value = [...new Set([...model.value, ...accepted])]
  // keep what was refused in the box, so it can be fixed instead of retyped
  draft.value = refused.length ? parts.filter(p => !accepted.includes(p)).join(', ') : ''
  rejected.value = refused[0] ?? ''
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
