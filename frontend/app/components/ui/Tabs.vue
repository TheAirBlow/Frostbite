<template>
  <div role="tablist" class="tabs tabs-border">
    <button v-for="t in tabs" :key="t.id" role="tab" type="button" class="tab gap-2 whitespace-nowrap" :class="{ 'tab-active font-semibold': model === t.id }" @click="model = t.id">
      <Icon v-if="t.icon" :name="t.icon" size="13" />
      {{ tr(t.label) }}
      <span v-if="t.count !== undefined" class="badge badge-xs badge-ghost">{{ t.count }}</span>
    </button>
  </div>
</template>

<script setup lang="ts">
const { t: tr } = useT()
defineProps<{ tabs: { id: string, label: string, icon?: string, count?: number }[] }>()
const model = defineModel<string>({ required: true })
</script>
