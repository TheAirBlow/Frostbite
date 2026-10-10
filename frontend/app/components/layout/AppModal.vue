<template>
  <dialog ref="dialog" class="modal" :class="{ 'modal-bottom sm:modal-middle': !fullscreen }" @close="onClose" @cancel.prevent="requestClose">
    <div class="modal-box flex flex-col gap-0 p-0" :class="[maxWidth, height, fullscreen ? 'h-dvh max-h-dvh w-screen max-w-none rounded-none sm:h-auto sm:max-h-[calc(100dvh-5em)] sm:w-11/12 sm:rounded-box' : '']">
      <header class="border-base-300 flex shrink-0 items-center justify-between gap-3 border-b px-5 py-4">
        <slot name="header">
          <div class="min-w-0">
            <h3 class="font-display truncate text-xl font-semibold">{{ t(title) }}</h3>
            <p v-if="subtitle" class="text-base-content/60 truncate text-sm">{{ t(subtitle) }}</p>
          </div>
        </slot>
        <button v-if="!hideClose" class="btn btn-sm btn-circle btn-ghost shrink-0" :aria-label="$t('Close')" @click="requestClose">
          <Icon name="fa6-solid:xmark" size="14" />
        </button>
      </header>
      <div class="min-h-0 flex-1 overflow-y-auto p-5">
        <slot />
      </div>
      <footer v-if="$slots.footer" class="border-base-300 shrink-0 border-t px-5 py-3">
        <slot name="footer" />
      </footer>
    </div>
    <div class="modal-backdrop">
      <button type="button" @click="requestClose">{{ $t('Close') }}</button>
    </div>
  </dialog>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ title?: string, subtitle?: string, maxWidth?: string, height?: string, fullscreen?: boolean, hideClose?: boolean }>(), {
  title: '',
  subtitle: '',
  maxWidth: 'max-w-lg',
  height: '',
})
const emit = defineEmits<{ close: [] }>()
const { t } = useT()

const dialog = useTemplateRef('dialog')
let fallback: ReturnType<typeof setTimeout> | undefined

onMounted(() => dialog.value?.showModal())
onScopeDispose(() => clearTimeout(fallback))

// let the closing transition play before the parent drops the component
function requestClose() {
  dialog.value?.close()
}

function onClose() {
  const el = dialog.value
  if (!el) return emit('close')
  let done = false
  const finish = () => {
    if (done) return
    done = true
    emit('close')
  }
  el.addEventListener('transitionend', finish, { once: true })
  fallback = setTimeout(finish, 400)
}
</script>
