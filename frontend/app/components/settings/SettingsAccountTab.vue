<template>
  <form class="flex max-w-md flex-col gap-4" @submit.prevent="save">
    <div class="surface flex items-center gap-3 p-4">
      <span class="bg-primary/15 text-primary grid size-12 place-items-center rounded-2xl text-lg font-semibold uppercase">{{ auth.me?.username[0] }}</span>
      <div><p class="font-display text-xl font-semibold">{{ auth.me?.username }}</p><p class="text-base-content/60 text-sm capitalize">{{ auth.me?.role }}</p></div>
    </div>
    <h3 class="font-display text-lg font-semibold">{{ $t('Change password') }}</h3>
    <FormField label="Current password"><input v-model="form.old" type="password" class="input w-full" autocomplete="current-password" required></FormField>
    <FormField label="New password" hint="At least 8 characters."><input v-model="form.new" type="password" class="input w-full" autocomplete="new-password" minlength="8" required></FormField>
    <button class="btn btn-primary self-start" :class="{ 'btn-disabled': saving }">{{ $t('Change password') }}</button>
  </form>
</template>

<script setup lang="ts">
const auth = useAuthStore()
const form = reactive({ old: '', new: '' })
const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi('/auth/password', { method: 'PUT', body: { ...form } })
  form.old = ''
  form.new = ''
}, 'Password changed.')
</script>
