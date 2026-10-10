<template>
  <Teleport to="body">
    <Transition name="drawer" @after-leave="emit('closed')">
      <div v-if="open" class="fixed inset-0 z-50 flex justify-end">
        <button type="button" class="drawer-backdrop absolute inset-0 bg-black/55 backdrop-blur-[2px]" :aria-label="$t('Close')" @click="emit('close')" />
        <aside class="drawer-panel bg-base-100 border-base-300 relative flex h-full w-full flex-col border-l shadow-2xl" :class="width">
          <header class="border-base-300 flex shrink-0 items-start justify-between gap-3 border-b p-4">
            <div class="min-w-0">
              <h3 v-if="title" class="font-display truncate text-xl font-semibold">{{ t(title) }}</h3>
              <p v-if="subtitle" class="text-base-content/60 truncate text-sm">{{ t(subtitle) }}</p>
            </div>
            <div class="flex shrink-0 items-center gap-1">
              <slot name="actions" />
              <button class="btn btn-sm btn-circle btn-ghost" :aria-label="$t('Close')" @click="emit('close')">
                <Icon name="fa6-solid:xmark" size="14" />
              </button>
            </div>
          </header>
          <div v-if="$slots.tabs" class="border-base-300 shrink-0 overflow-x-auto border-b px-4">
            <slot name="tabs" />
          </div>
          <div class="min-h-0 flex-1 overflow-y-auto p-4">
            <slot />
          </div>
          <footer v-if="$slots.footer" class="border-base-300 bg-base-100 shrink-0 border-t p-3">
            <slot name="footer" />
          </footer>
        </aside>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ open: boolean, title?: string, subtitle?: string, width?: string }>(), {
  title: '',
  subtitle: '',
  width: 'max-w-xl',
})
const emit = defineEmits<{ close: [], closed: [] }>()
const { t } = useT()

useEventListener(() => (import.meta.client ? window : undefined), 'keydown', (e: KeyboardEvent) => {
  if (e.key === 'Escape' && !document.querySelector('dialog[open]')) emit('close')
})
</script>

<style scoped>
.drawer-enter-active,
.drawer-leave-active {
  transition: opacity 0.2s ease;
}
.drawer-enter-active .drawer-panel,
.drawer-leave-active .drawer-panel {
  transition: transform 0.25s cubic-bezier(0.22, 1, 0.36, 1);
}
.drawer-enter-from,
.drawer-leave-to {
  opacity: 0;
}
.drawer-enter-from .drawer-panel,
.drawer-leave-to .drawer-panel {
  transform: translateX(100%);
}
@media (prefers-reduced-motion: reduce) {
  .drawer-enter-active,
  .drawer-leave-active,
  .drawer-enter-active .drawer-panel,
  .drawer-leave-active .drawer-panel {
    transition: none;
  }
}
</style>
