<template>
  <div class="flex flex-col gap-2">
    <div v-for="i in rows" :key="i" class="skeleton w-full" :style="{ height: `${height}px` }" />
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ rows?: number, height?: number }>(), { rows: 3, height: 56 })
</script>
