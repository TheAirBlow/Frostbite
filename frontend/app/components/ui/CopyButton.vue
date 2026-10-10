<template>
  <button type="button" class="btn btn-ghost btn-xs btn-square" :title="t(label)" @click.stop="copy">
    <Icon :name="copied ? 'fa6-solid:check' : 'fa6-regular:copy'" size="13" :class="{ 'text-success': copied }" />
  </button>
</template>

<script setup lang="ts">
const props = withDefaults(defineProps<{ value: string, label?: string }>(), { label: 'Copy' })
const toast = useToast()
const { t } = useT()
const { copy: doCopy, copied } = useClipboard({ copiedDuring: 1500 })

async function copy() {
  await doCopy(props.value)
  toast.info('Copied to the clipboard.')
}
</script>
