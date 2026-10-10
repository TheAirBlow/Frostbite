<template>
  <div class="flex max-w-2xl flex-col gap-4">
    <p class="text-base-content/60 text-sm">{{ $t('Tokens let scripts and bots use the API with your permissions. Send one as the header Authorization: Bearer fbt_…') }}</p>
    <form class="flex gap-2" @submit.prevent="create">
      <input v-model="name" class="input input-sm flex-1" :placeholder="$t('What is it for?')" required>
      <button class="btn btn-sm btn-primary" :class="{ 'btn-disabled': creating }">{{ $t('Create token') }}</button>
    </form>
    <div v-if="fresh" class="alert alert-success alert-soft">
      <Icon name="fa6-solid:key" size="14" />
      <div class="min-w-0 flex-1"><p class="text-sm font-medium">{{ $t('Copy it now, it will not be shown again.') }}</p><p class="font-mono text-xs break-all">{{ fresh }}</p></div>
      <CopyButton :value="fresh" />
    </div>
    <Skeleton v-if="pending" :rows="2" :height="44" />
    <div v-else-if="tokens?.length" class="flex flex-col gap-2">
      <div v-for="t in tokens" :key="t.id" class="surface flex items-center gap-3 p-3">
        <Icon name="fa6-solid:key" size="14" class="text-base-content/50" />
        <div class="min-w-0 flex-1"><p class="font-medium">{{ t.name }}</p><p class="text-base-content/50 text-xs">created {{ formatRelative(t.created_at) }} · {{ t.last_used_at ? `used ${formatRelative(t.last_used_at)}` : 'never used' }}</p></div>
        <ConfirmButton class="btn btn-ghost btn-xs text-error" confirm-label="Revoke?" @confirmed="revoke(t.id)"><Icon name="fa6-solid:trash" size="12" /></ConfirmButton>
      </div>
    </div>
    <p v-else class="text-base-content/50 text-sm">{{ $t('No tokens yet.') }}</p>
  </div>
</template>

<script setup lang="ts">
import type { ApiToken } from '~/types/api'

const name = ref('')
const fresh = ref('')
const { data: tokens, pending, refresh } = useAsyncData('tokens', () => useApi<ApiToken[]>('/auth/tokens'))

const { loading: creating, run: create } = useAsyncAction(async () => {
  const t = await useApi<ApiToken>('/auth/tokens', { method: 'POST', body: { name: name.value } })
  fresh.value = t.token ?? ''
  name.value = ''
  await refresh()
})
const { run: revoke } = useAsyncAction(async (id: number) => {
  await useApi(`/auth/tokens/${id}`, { method: 'DELETE' })
  await refresh()
}, 'Token revoked.')
</script>
