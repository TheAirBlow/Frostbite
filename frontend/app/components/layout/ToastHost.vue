<template>
  <div class="toast toast-end toast-bottom z-[70] mb-16 sm:mb-0">
    <TransitionGroup name="toast">
      <div v-for="t in toasts" :key="t.id" class="alert cursor-pointer shadow-lg" :class="alertClass[t.type]" @click="dismiss(t.id)">
        <Icon :name="icon[t.type]!" size="16" />
        <span class="text-sm">{{ t.message }}</span>
      </div>
    </TransitionGroup>
  </div>
</template>

<script setup lang="ts">
const { toasts, dismiss } = useToast()

const alertClass: Record<string, string> = { success: 'alert-success', error: 'alert-error', info: 'alert-info' }
const icon: Record<string, string> = {
  success: 'fa6-solid:circle-check',
  error: 'fa6-solid:circle-exclamation',
  info: 'fa6-solid:circle-info',
}
</script>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(8px);
}
</style>
