<template>
  <div class="flex flex-col gap-3">
    <div v-if="basic.length" class="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
      <SchemaField v-for="f in basic" :key="f.path" :field="f" :prefix="prefix" :model="model" @set="set" />
    </div>
    <!-- advanced knobs are tucked away, never removed -->
    <Advanced v-if="extra.length" :title="moreTitle">
      <div class="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
        <SchemaField v-for="f in extra" :key="f.path" :field="f" :prefix="prefix" :model="model" @set="set" />
      </div>
    </Advanced>
  </div>
</template>

<script setup lang="ts">
import type { SchemaField as Field } from '~/types/api'

// Renders the form definitions the panel derives from the spec structs.
// "show" rules look up a sibling value first and the surrounding context second (e.g. the inbound protocol).
// `prefix` is where the model sits in the API body (options.), so errors find their fields.
const props = withDefaults(defineProps<{ fields: Field[], context?: Record<string, string>, prefix?: string, moreTitle?: string }>(), {
  prefix: '',
  moreTitle: 'More options',
  context: undefined,
})
const model = defineModel<Record<string, unknown>>({ required: true })

function get(path: string): unknown {
  return path.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), model.value)
}

function set(path: string, value: unknown) {
  const next = { ...model.value }
  const keys = path.split('.')
  let cur: Record<string, unknown> = next
  for (const k of keys.slice(0, -1)) {
    cur[k] = { ...((cur[k] as Record<string, unknown>) ?? {}) }
    cur = cur[k] as Record<string, unknown>
  }
  cur[keys[keys.length - 1]!] = value
  model.value = next
}

const visible = computed(() => props.fields.filter((f) => {
  if (!f.show) return true
  return Object.entries(f.show).every(([key, accepted]) => {
    const v = props.context?.[key] ?? String(get(key) ?? '')
    return accepted.includes(v)
  })
}))
const basic = computed(() => visible.value.filter(f => !f.advanced))
const extra = computed(() => visible.value.filter(f => f.advanced))
</script>
