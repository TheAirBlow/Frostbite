<template>
  <span class="badge badge-sm gap-1.5 whitespace-nowrap" :class="meta.badge">
    <Icon :name="meta.icon" size="10" />
    {{ t(`status.${status}`) === `status.${status}` ? meta.label : t(`status.${status}`) }}
  </span>
</template>

<script setup lang="ts">
const props = defineProps<{ status: string }>()
const { t } = useT()
const meta = computed(() => statusMeta[props.status] ?? { label: props.status, badge: 'badge-ghost', icon: 'fa6-solid:circle' })
</script>
