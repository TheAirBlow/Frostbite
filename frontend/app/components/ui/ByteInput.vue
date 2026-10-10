<template>
  <div class="flex items-center gap-2">
    <label class="input min-w-0 flex-1" :class="{ 'opacity-50': unlimited }">
      <input v-model.number="amount" type="number" min="0" step="any" :disabled="unlimited" class="min-w-0" :placeholder="unlimited ? '∞' : '0'" :aria-label="$t('Amount')">
      <select v-model="unit" :disabled="unlimited" class="bg-transparent" :aria-label="$t('Unit')">
        <option v-for="u in units" :key="u.label" :value="u.label">{{ u.label }}</option>
      </select>
    </label>
    <label v-if="allowUnlimited" class="flex shrink-0 cursor-pointer items-center gap-1.5 text-xs">
      <input type="checkbox" class="checkbox checkbox-xs checkbox-primary" :checked="unlimited" @change="toggleUnlimited(($event.target as HTMLInputElement).checked)">
      {{ $t('Unlimited') }}
    </label>
  </div>
</template>

<script setup lang="ts">
const props = withDefaults(defineProps<{ allowUnlimited?: boolean }>(), { allowUnlimited: true })
// bytes; 0 means unlimited
const model = defineModel<number>({ default: 0 })

const units = [
  { label: 'MB', size: 1024 ** 2 },
  { label: 'GB', size: 1024 ** 3 },
  { label: 'TB', size: 1024 ** 4 },
]

function pickUnit(bytes: number) {
  if (bytes >= 1024 ** 4 && bytes % 1024 ** 4 === 0) return 'TB'
  if (bytes >= 1024 ** 3) return 'GB'
  return bytes ? 'MB' : 'GB'
}

const unit = ref(pickUnit(model.value))
const unlimited = computed(() => props.allowUnlimited && model.value === 0)
const size = computed(() => units.find(u => u.label === unit.value)!.size)

// a value that arrives after the first render (a form that loads its data) picks the unit that reads best
let typed = false
watch(model, (v, old) => {
  if (typed) {
    typed = false
    return
  }
  if (old === 0 && v > 0) unit.value = pickUnit(v)
})

const amount = computed({
  get: () => (model.value ? Number((model.value / size.value).toFixed(2)) : null),
  set: (v: number | null) => {
    typed = true
    model.value = Math.max(0, Math.round((v || 0) * size.value))
  },
})

function toggleUnlimited(on: boolean) {
  model.value = on ? 0 : 10 * 1024 ** 3
  if (!on) unit.value = 'GB'
}
</script>
