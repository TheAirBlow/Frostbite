<template>
  <Tabs v-model="model" :tabs="tabs" />
</template>

<script setup lang="ts">
const model = defineModel<string>({ required: true })

const tabs = [
  { id: 'overview', label: 'Overview', icon: 'fa6-solid:gauge-high' },
  { id: 'settings', label: 'Settings', icon: 'fa6-solid:sliders' },
  { id: 'links', label: 'Connections', icon: 'fa6-solid:link' },
  { id: 'traffic', label: 'Traffic', icon: 'fa6-solid:chart-area' },
  { id: 'devices', label: 'Devices', icon: 'fa6-solid:mobile-screen' },
]
</script>
