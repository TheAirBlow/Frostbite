<template>
  <Transition name="fade">
    <div v-if="ctx?.banner.value" class="alert alert-error alert-soft py-2 text-sm" role="alert">
      <Icon name="fa6-solid:triangle-exclamation" size="14" />
      <span class="min-w-0 break-words">{{ ctx.banner.value }}</span>
    </div>
  </Transition>
</template>

<script setup lang="ts">
const ctx = inject(formKey, null)
</script>
