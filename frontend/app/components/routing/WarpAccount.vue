<template>
  <div class="bg-base-100 border-base-300 flex flex-col gap-3 rounded-xl border p-3">
    <div class="flex items-center gap-2">
      <Icon name="fa6-solid:cloud" size="15" class="text-primary" />
      <p class="font-medium">Cloudflare WARP</p>
      <span v-if="status?.registered" class="badge badge-sm" :class="status.type === 'unlimited' ? 'badge-success badge-soft' : 'badge-ghost'">{{ status.type === 'unlimited' ? 'WARP+' : 'free' }}</span>
    </div>

    <template v-if="status?.registered">
      <p class="text-base-content/60 text-xs">One account is shared by every WARP outbound. It lives on the panel and daemons dial Cloudflare directly, no interface to set up on the node. Address {{ status.address_v4 }}.</p>
      <form class="flex gap-2" @submit.prevent="setLicense()">
        <input v-model="license" class="input input-sm flex-1 font-mono" :placeholder="status.license ? `WARP+ key (current ${status.license})` : 'WARP+ license key (optional)'">
        <button class="btn btn-sm" :class="{ 'btn-disabled': !license || working }">{{ $t('Apply') }}</button>
      </form>
      <ConfirmButton class="btn btn-ghost btn-xs self-start text-error" confirm-label="New identity, new IP" @confirmed="register(true)">{{ $t('Replace the account') }}</ConfirmButton>
    </template>
    <template v-else>
      <p class="text-base-content/60 text-xs">{{ $t('No account yet. Registering one takes a second and needs the panel to reach Cloudflare.') }}</p>
      <button type="button" class="btn btn-primary btn-sm self-start" :class="{ 'btn-disabled': working }" @click="register(false)"><span v-if="working" class="loading loading-spinner loading-xs" /> {{ $t('Register a WARP account') }}</button>
    </template>
    <p class="text-base-content/50 text-xs">{{ $t('WARP needs UDP to Cloudflare from the node. Some networks block it.') }}</p>
  </div>
</template>

<script setup lang="ts">
import type { WarpStatus } from '~/types/api'

const emit = defineEmits<{ changed: [registered: boolean] }>()
const { data: status, refresh } = useAsyncData('warp', () => useApi<WarpStatus>('/warp'))
const license = ref('')

watch(status, s => emit('changed', !!s?.registered), { immediate: true })

const { loading: working, run: register } = useAsyncAction(async (replace: boolean) => {
  await useApi('/warp/register' + (replace ? '?replace=1' : ''), { method: 'POST' })
  await refresh()
}, 'WARP account ready.')

const { run: setLicense } = useAsyncAction(async () => {
  await useApi('/warp/license', { method: 'PUT', body: { license: license.value } })
  license.value = ''
  await refresh()
}, 'License applied.')
</script>
