<template>
  <div class="bg-base-100 border-base-300 flex flex-col gap-3 rounded-xl border p-3">
    <div class="flex items-center gap-2">
      <Icon name="fa6-solid:cloud" size="15" class="text-primary" />
      <p class="font-medium">Cloudflare WARP</p>
      <span v-if="status?.registered" class="badge badge-sm" :class="status.type === 'unlimited' ? 'badge-success badge-soft' : 'badge-ghost'">{{ status.type === 'unlimited' ? 'WARP+' : 'free' }}</span>
    </div>

    <template v-if="status?.registered">
      <p class="text-base-content/60 text-xs">One account is shared by every WARP outbound. It lives on the panel and daemons dial Cloudflare directly, no interface to set up on the node. Address {{ status.address_v4 }}.</p>
      <form novalidate @submit.prevent="setLicense()">
        <FormField label="WARP+ license key" name="license" hint="Optional. Unlocks the faster WARP+ network.">
          <div class="join w-full">
            <input v-model="license" class="input join-item w-full font-mono" autocomplete="off" :placeholder="status.license ? `current ${status.license}` : 'xxxxxxxx-xxxxxxxx-xxxxxxxx'">
            <button class="btn join-item" :disabled="working">{{ $t('Apply') }}</button>
          </div>
        </FormField>
        <FormBanner class="mt-2" />
      </form>
      <ConfirmButton class="btn btn-ghost btn-xs self-start text-error" confirm-label="New identity, new IP" @confirmed="register(true)">{{ $t('Replace the account') }}</ConfirmButton>
    </template>
    <template v-else>
      <p class="text-base-content/60 text-xs">{{ $t('No account yet. Registering one takes a second and needs the panel to reach Cloudflare.') }}</p>
      <button type="button" class="btn btn-primary btn-sm self-start" :disabled="working" @click="register(false)"><span v-if="working" class="loading loading-spinner loading-xs" /> {{ $t('Register a WARP account') }}</button>
    </template>
    <p class="text-base-content/50 text-xs">{{ $t('WARP needs UDP to Cloudflare from the node. Some networks block it.') }}</p>
  </div>
</template>

<script setup lang="ts">
import type { WarpStatus } from '~/types/api'

const emit = defineEmits<{ changed: [registered: boolean] }>()
const { data: status, refresh } = useAsyncData('warp', () => useApi<WarpStatus>('/warp'))
const license = ref('')
const formApi = useForm(() => ({ license: license.value }), v => problems({
  license: checkRequired(v.license, 'Paste a license key') ?? (/^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$/.test(v.license.trim()) ? undefined : 'A key looks like xxxxxxxx-xxxxxxxx-xxxxxxxx'),
}))

watch(status, s => emit('changed', !!s?.registered), { immediate: true })

const { loading: working, run: register } = useAsyncAction(async (replace: boolean) => {
  await useApi('/warp/register' + (replace ? '?replace=1' : ''), { method: 'POST' })
  await refresh()
}, 'WARP account ready.')

const { run: setLicense } = useAsyncAction(async () => {
  await useApi('/warp/license', { method: 'PUT', body: { license: license.value } })
  license.value = ''
  await refresh()
}, 'License applied.', formApi)
</script>
