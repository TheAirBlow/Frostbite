<template>
  <div class="flex max-w-xl flex-col gap-4">
    <div class="surface flex items-center gap-4 p-5">
      <span class="grid size-14 place-items-center rounded-2xl bg-gradient-to-br from-primary/90 to-secondary/90 text-primary-content"><Icon name="fa6-solid:snowflake" size="26" /></span>
      <div><p class="font-display text-2xl font-semibold">Frostbite</p><p class="text-base-content/60 text-sm">{{ $t('Multi node VPN panel') }}</p></div>
    </div>
    <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
      <dt class="text-base-content/50">{{ $t('Panel address') }}</dt><dd class="font-mono text-xs break-all">{{ origin }}</dd>
      <dt class="text-base-content/50">{{ $t('Daemons connect to') }}</dt><dd class="font-mono text-xs break-all">{{ origin }}/api/link</dd>
      <dt class="text-base-content/50">{{ $t('Cores') }}</dt><dd><span v-for="c in cores" :key="c.kind" class="badge badge-sm badge-primary badge-soft mr-1">{{ c.display_name }}</span></dd>
    </dl>
    <p class="text-base-content/60 text-sm">{{ $t('Set FROSTBITE_SERVER_PUBLIC_URL when the panel sits behind a proxy, so share links and install commands carry the right address.') }}</p>
  </div>
</template>

<script setup lang="ts">
import type { CoreInfo } from '~/types/api'

const origin = import.meta.client ? window.location.origin : ''
const { data: cores } = useAsyncData('cores', () => useApi<CoreInfo[]>('/cores'), { default: () => [] })
</script>
