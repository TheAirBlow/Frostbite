<template>
  <div class="flex max-w-3xl flex-col gap-4">
    <div class="flex items-center justify-between gap-2">
      <p class="text-base-content/60 text-sm"><b>{{ $t('Owners') }}</b> {{ $t('can do everything.') }} <b>{{ $t('Admins') }}</b> {{ $t('manage servers and users.') }} <b>{{ $t('Resellers') }}</b> {{ $t('only see and manage their own users, within a quota.') }}</p>
      <button class="btn btn-sm btn-primary shrink-0" @click="edit = blank()"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add') }}</button>
    </div>
    <Skeleton v-if="pending" :rows="3" :height="56" />
    <div v-else class="flex flex-col gap-2">
      <button v-for="a in admins" :key="a.id" class="surface hover:border-primary/50 flex items-center gap-3 p-3 text-left transition" @click="edit = { ...a, password: '' }">
        <span class="bg-base-300 grid size-9 place-items-center rounded-xl text-sm font-semibold uppercase">{{ a.username[0] }}</span>
        <div class="min-w-0 flex-1"><p class="font-medium">{{ a.username }} <span v-if="a.id === auth.me?.id" class="badge badge-xs badge-primary badge-soft">{{ $t('you') }}</span></p><p class="text-base-content/50 text-xs">{{ a.note || '—' }}<template v-if="a.role === 'reseller' && a.user_quota"> · up to {{ a.user_quota }} users</template><template v-if="a.role === 'reseller' && a.traffic_quota"> · {{ formatBytes(a.traffic_quota, 0) }} to give out</template></p></div>
        <span class="badge badge-sm capitalize" :class="a.role === 'owner' ? 'badge-secondary badge-soft' : a.role === 'admin' ? 'badge-primary badge-soft' : 'badge-ghost'">{{ a.role }}</span>
        <span v-if="!a.enabled" class="badge badge-sm badge-neutral">{{ $t('disabled') }}</span>
      </button>
    </div>

    <AppModal v-if="edit" :title="edit.id ? edit.username : 'New account'" max-width="max-w-md" @close="edit = null">
      <form id="admin-form" class="flex flex-col gap-3" @submit.prevent="save">
        <FormField v-if="!edit.id" label="Username"><input v-model="edit.username" class="input w-full" required></FormField>
        <FormField v-if="!edit.id" label="Password"><input v-model="edit.password" type="password" class="input w-full" minlength="8" required></FormField>
        <FormField label="Role"><select v-model="edit.role" class="select w-full"><option value="owner">{{ $t('Owner') }}</option><option value="admin">{{ $t('Admin') }}</option><option value="reseller">{{ $t('Reseller') }}</option></select></FormField>
        <template v-if="edit.role === 'reseller'">
          <FormField label="User quota" hint="Empty means no cap."><input v-model.number="edit.user_quota" type="number" min="0" class="input w-full"></FormField>
          <FormField label="Traffic to hand out" hint="The total of all their users' limits. Setting it also stops them creating unlimited users."><ByteInput :model-value="edit.traffic_quota ?? 0" @update:model-value="edit.traffic_quota = $event || null" /></FormField>
        </template>
        <FormField label="Note"><input v-model="edit.note" class="input w-full"></FormField>
        <ToggleRow v-if="edit.id" v-model="edit.enabled" label="Enabled" />
        <FormField v-if="edit.id" label="Set a new password" hint="Leave empty to keep the current one."><input v-model="edit.password" type="password" class="input w-full" minlength="8" autocomplete="new-password"></FormField>
      </form>
      <template #footer>
        <div class="flex items-center justify-between">
          <ConfirmButton v-if="edit.id && edit.id !== auth.me?.id" class="btn btn-ghost text-error" confirm-label="Delete?" @confirmed="remove">{{ $t('Delete') }}</ConfirmButton>
          <span v-else />
          <button form="admin-form" class="btn btn-primary">{{ $t('Save') }}</button>
        </div>
      </template>
    </AppModal>
  </div>
</template>

<script setup lang="ts">
import type { Admin } from '~/types/api'

type Draft = Partial<Admin> & { password: string }
const auth = useAuthStore()
const { data: admins, pending, refresh } = useAsyncData('admins', () => useApi<Admin[]>('/admins'))
const edit = ref<Draft | null>(null)
const blank = (): Draft => ({ username: '', password: '', role: 'admin', enabled: true, user_quota: null, traffic_quota: null, note: '' })

const { run: save } = useAsyncAction(async () => {
  const d = edit.value!
  if (d.id) {
    await useApi(`/admins/${d.id}`, { method: 'PUT', body: { role: d.role, enabled: d.enabled, user_quota: d.user_quota || null, traffic_quota: d.traffic_quota || null, note: d.note } })
    if (d.password) await useApi(`/admins/${d.id}/password`, { method: 'PUT', body: { new: d.password } })
  }
  else {
    await useApi('/admins', { method: 'POST', body: { username: d.username, password: d.password, role: d.role, user_quota: d.user_quota || null, traffic_quota: d.traffic_quota || null, note: d.note } })
  }
  edit.value = null
  await refresh()
}, 'Saved.')

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/admins/${edit.value!.id}`, { method: 'DELETE' })
  edit.value = null
  await refresh()
}, 'Account deleted.')
</script>
