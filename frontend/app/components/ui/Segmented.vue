<template>
  <div class="join" role="group">
    <button
      v-for="o in options"
      :key="o.value"
      type="button"
      class="btn join-item"
      :class="[size, model === o.value ? 'btn-primary' : 'btn-ghost bg-base-200']"
      @click="model = o.value"
    >
      <Icon v-if="o.icon" :name="o.icon" size="13" />
      {{ t(o.label) }}
    </button>
  </div>
</template>

<script setup lang="ts">
const { t } = useT()
withDefaults(defineProps<{ options: { value: string, label: string, icon?: string }[], size?: string }>(), { size: 'btn-sm' })
const model = defineModel<string>({ required: true })
</script>
