<template>
  <AppModal :title="`${daemon.name} logs`" :subtitle="coreLabels[daemon.kind]" max-width="max-w-4xl" @close="emit('close')">
    <div class="mb-3 flex flex-wrap items-center gap-2">
      <select v-model.number="lines" class="select select-sm w-auto"><option :value="100">{{ $t('Last 100') }}</option><option :value="300">{{ $t('Last 300') }}</option><option :value="1000">{{ $t('Last 1000') }}</option></select>
      <button class="btn btn-sm" :class="{ 'btn-disabled': loading }" @click="load"><span v-if="loading" class="loading loading-spinner loading-xs" /><Icon v-else name="fa6-solid:rotate" size="12" /> {{ $t('Refresh') }}</button>
      <label class="flex cursor-pointer items-center gap-2 text-sm"><input v-model="follow" type="checkbox" class="toggle toggle-xs toggle-primary"> {{ $t('Follow') }}</label>
      <CopyButton :value="text" class="ml-auto" />
    </div>
    <pre ref="box" class="bg-base-300/60 h-[55vh] overflow-auto rounded-lg p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap">{{ text || (loading ? 'Loading…' : 'Nothing logged yet.') }}</pre>
  </AppModal>
</template>

<script setup lang="ts">
import type { CommandResult, Daemon } from '~/types/api'

const props = defineProps<{ daemon: Daemon }>()
const emit = defineEmits<{ close: [] }>()
const box = useTemplateRef('box')
const lines = ref(300)
const follow = ref(false)
const text = ref('')

const { loading, run: load } = useAsyncAction(async () => {
  const r = await useApi<CommandResult>(`/daemons/${props.daemon.id}/logs`, { query: { lines: lines.value } })
  text.value = r.output ?? ''
  await nextTick()
  if (box.value) box.value.scrollTop = box.value.scrollHeight
})

watch(lines, load)
onMounted(load)
let timer: ReturnType<typeof setInterval> | undefined
watch(follow, (on) => {
  clearInterval(timer)
  if (on) timer = setInterval(load, 3000)
})
onScopeDispose(() => clearInterval(timer))
</script>
