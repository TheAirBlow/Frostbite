<template>
  <div class="flex flex-col gap-1">
    <p class="fieldset-legend">{{ label }}</p>
    <div class="flex flex-wrap gap-1.5">
      <button type="button" class="btn btn-xs rounded-full" :class="!model.length ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="model = []">{{ $t('Everything') }}</button>
      <button v-for="e in events" :key="e.id" type="button" class="btn btn-xs rounded-full" :class="model.includes(e.id) ? 'btn-primary' : 'btn-ghost bg-base-200'" @click="toggle(e.id)">{{ e.label }}</button>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ label: string }>()
const model = defineModel<string[]>({ default: () => [] })

const events = [
  { id: 'user.expiring', label: 'Expiring soon' },
  { id: 'user.usage', label: 'Traffic warning' },
  { id: 'user.limited', label: 'Limit reached' },
  { id: 'user.expired', label: 'Expired' },
  { id: 'user.blocked', label: 'IP limit hit' },
  { id: 'node.offline', label: 'Daemon offline' },
  { id: 'node.online', label: 'Daemon back' },
]

function toggle(id: string) {
  model.value = model.value.includes(id) ? model.value.filter(x => x !== id) : [...model.value, id]
}
</script>
