<template>
  <ToggleRow v-if="field.type === 'bool'" class="sm:col-span-2" :label="field.label" :hint="field.hint" :model-value="!!value" @update:model-value="emit('set', field.path, $event)" />
  <FormField v-else :label="field.label" :hint="field.hint" :name="prefix + field.path" :class="field.type === 'list' || field.type === 'map' ? 'sm:col-span-2' : ''">
    <select v-if="field.options" class="select w-full" :value="String(value ?? '')" @change="emit('set', field.path, ($event.target as HTMLSelectElement).value)">
      <option v-for="o in field.options" :key="o" :value="o">{{ o ? t(o) : t('(none)') }}</option>
    </select>
    <ChipInput v-else-if="field.type === 'list'" :model-value="(value as string[] | undefined) ?? []" @update:model-value="emit('set', field.path, $event)" />
    <textarea v-else-if="field.type === 'map'" class="textarea w-full font-mono text-xs" rows="3" :placeholder="t('Header: value')" :value="mapText(value)" @input="emit('set', field.path, parseMap(($event.target as HTMLTextAreaElement).value))" />
    <input v-else-if="field.type === 'number'" type="number" min="0" class="input w-full" :value="(value as number | undefined) || ''" @input="emit('set', field.path, Number(($event.target as HTMLInputElement).value) || 0)">
    <input v-else type="text" class="input w-full" :value="String(value ?? '')" @input="emit('set', field.path, ($event.target as HTMLInputElement).value)">
  </FormField>
</template>

<script setup lang="ts">
import type { SchemaField as Field } from '~/types/api'

const props = defineProps<{ field: Field, prefix: string, model: Record<string, unknown> }>()
const emit = defineEmits<{ set: [path: string, value: unknown] }>()
const { t } = useT()

const value = computed(() => props.field.path.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), props.model))

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
