<template>
  <div class="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
    <template v-for="f in visible" :key="f.path">
      <ToggleRow v-if="f.type === 'bool'" class="sm:col-span-2" :label="f.label" :hint="f.hint" :model-value="!!get(f.path)" @update:model-value="set(f.path, $event)" />
      <FormField v-else :label="f.label" :hint="f.hint" :class="f.type === 'list' || f.type === 'map' ? 'sm:col-span-2' : ''">
        <select v-if="f.options" class="select w-full" :value="String(get(f.path) ?? '')" @change="set(f.path, ($event.target as HTMLSelectElement).value)">
          <option v-for="o in f.options" :key="o" :value="o">{{ o || '(none)' }}</option>
        </select>
        <ChipInput v-else-if="f.type === 'list'" :model-value="(get(f.path) as string[] | undefined) ?? []" @update:model-value="set(f.path, $event)" />
        <textarea v-else-if="f.type === 'map'" class="textarea w-full font-mono text-xs" rows="3" :placeholder="$t('Header: value')" :value="mapText(get(f.path))" @input="set(f.path, parseMap(($event.target as HTMLTextAreaElement).value))" />
        <input v-else-if="f.type === 'number'" type="number" class="input w-full" :value="(get(f.path) as number | undefined) || ''" @input="set(f.path, Number(($event.target as HTMLInputElement).value) || 0)">
        <input v-else type="text" class="input w-full" :value="String(get(f.path) ?? '')" @input="set(f.path, ($event.target as HTMLInputElement).value)">
      </FormField>
    </template>
  </div>
</template>

<script setup lang="ts">
import type { SchemaField } from '~/types/api'

// Renders the form definitions the panel derives from the spec structs.
// "show" rules look up a sibling value first and the surrounding context second (e.g. the inbound protocol).
const props = defineProps<{ fields: SchemaField[], context?: Record<string, string> }>()
const model = defineModel<Record<string, unknown>>({ required: true })
const prefs = usePreferencesStore()

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
  if (f.advanced && !prefs.advanced) return false
  if (!f.show) return true
  return Object.entries(f.show).every(([key, accepted]) => {
    const v = props.context?.[key] ?? String(get(key) ?? '')
    return accepted.includes(v)
  })
}))

function mapText(v: unknown): string {
  return v && typeof v === 'object' ? Object.entries(v as Record<string, string>).map(([k, x]) => `${k}: ${x}`).join('\n') : ''
}

function parseMap(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const i = line.indexOf(':')
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return out
}
</script>
