<template>
  <form class="flex max-w-md flex-col gap-4" novalidate @submit.prevent="save()">
    <div class="surface flex items-center gap-3 p-4">
      <span class="bg-primary/15 text-primary grid size-12 place-items-center rounded-2xl text-lg font-semibold uppercase">{{ auth.me?.username[0] }}</span>
      <div><p class="font-display text-xl font-semibold">{{ auth.me?.username }}</p><p class="text-base-content/60 text-sm capitalize">{{ auth.me?.role }}</p></div>
    </div>
    <h3 class="font-display text-lg font-semibold">{{ $t('Change password') }}</h3>
    <FormField label="Current password" name="old" required><input v-model="form.old" type="password" class="input w-full" autocomplete="current-password"></FormField>
    <FormField label="New password" name="new" hint="At least 8 characters." required><input v-model="form.new" type="password" class="input w-full" autocomplete="new-password"></FormField>
    <FormField label="Repeat the new password" name="again" required><input v-model="form.again" type="password" class="input w-full" autocomplete="new-password"></FormField>
    <FormBanner />
    <button class="btn btn-primary self-start" :disabled="saving">{{ $t('Change password') }}</button>
  </form>
</template>

<script setup lang="ts">
const auth = useAuthStore()
const form = reactive({ old: '', new: '', again: '' })
const formApi = useForm(form, f => problems({
  old: checkRequired(f.old, 'Enter your current password'),
  new: checkPassword(f.new) ?? (f.new === f.old ? 'Pick a password you have not used just now' : undefined),
  again: f.again === f.new ? undefined : 'The two passwords differ',
}))
const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi('/auth/password', { method: 'PUT', body: { old: form.old, new: form.new } })
  form.old = ''
  form.new = ''
  form.again = ''
  formApi.reset()
}, 'Password changed.', formApi)
</script>
