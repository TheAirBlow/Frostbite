<template>
  <AppModal :title="`${daemon.name} config`" subtitle="What the daemon would run right now, secrets included." max-width="max-w-4xl" @close="emit('close')">
    <Skeleton v-if="pending" :rows="1" :height="300" />
    <template v-else>
      <div v-if="error" class="alert alert-error alert-soft"><Icon name="fa6-solid:triangle-exclamation" size="14" /><span class="text-sm">{{ error }}</span></div>
      <template v-else>
        <div class="mb-2 flex justify-end"><CopyButton :value="text" /></div>
        <pre class="bg-base-300/60 h-[60vh] overflow-auto rounded-lg p-3 font-mono text-xs leading-relaxed">{{ text }}</pre>
      </template>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import type { Daemon } from '~/types/api'

const props = defineProps<{ daemon: Daemon }>()
const emit = defineEmits<{ close: [] }>()

const text = ref('')
const error = ref('')
const pending = ref(true)

onMounted(async () => {
  try {
    text.value = JSON.stringify(await useApi(`/daemons/${props.daemon.id}/preview`), null, 2)
  }
  catch (e) {
    error.value = errorMessage(e)
  }
  finally {
    pending.value = false
  }
})
</script>
