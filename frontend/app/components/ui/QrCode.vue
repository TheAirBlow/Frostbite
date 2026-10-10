<template>
  <div class="inline-block rounded-xl bg-white p-2.5" :style="{ width: `${size}px`, height: `${size}px` }">
    <img v-if="src" :src="src" :width="size - 20" :height="size - 20" :alt="$t('QR code')">
  </div>
</template>

<script setup lang="ts">
import QRCode from 'qrcode'

const props = withDefaults(defineProps<{ value: string, size?: number }>(), { size: 180 })
const src = ref('')

watchEffect(async () => {
  if (!props.value) return
  src.value = await QRCode.toDataURL(props.value, { margin: 0, width: props.size * 2, errorCorrectionLevel: 'M' })
})
</script>
