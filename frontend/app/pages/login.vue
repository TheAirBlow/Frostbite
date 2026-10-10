<template>
  <div class="flex min-h-dvh items-center justify-center p-4">
    <form class="surface w-full max-w-sm p-7 shadow-2xl" novalidate @submit.prevent="submit">
      <div class="mb-6 flex flex-col items-center gap-3 text-center">
        <span class="grid size-14 place-items-center rounded-2xl bg-gradient-to-br from-primary/90 to-secondary/90 text-primary-content shadow-lg shadow-primary/25">
          <Icon name="fa6-solid:snowflake" size="26" />
        </span>
        <div>
          <h1 class="font-display text-3xl font-semibold tracking-tight">Frostbite</h1>
          <p class="text-base-content/60 text-sm">{{ t('login.subtitle') }}</p>
        </div>
      </div>

      <div class="flex flex-col gap-1">
        <FormField :label="t('login.username')" name="username">
          <input v-model="username" class="input w-full" autocomplete="username" autofocus>
        </FormField>
        <FormField :label="t('login.password')" name="password">
          <input v-model="password" type="password" class="input w-full" autocomplete="current-password">
        </FormField>
      </div>

      <FormBanner class="mt-3" />

      <button class="btn btn-primary mt-5 w-full" :disabled="loading">
        <span v-if="loading" class="loading loading-spinner loading-xs" />
        {{ t('login.button') }}
      </button>
      <div class="mt-4 flex justify-center"><LanguageSwitcher align="dropdown-top" /></div>
    </form>
  </div>
</template>

<script setup lang="ts">
definePageMeta({ layout: 'blank' })
useHead({ title: 'Sign in' })

const auth = useAuthStore()
const { t } = useT()
const username = ref('')
const password = ref('')
const formApi = useForm(() => ({ username: username.value, password: password.value }), v => problems({
  username: checkRequired(v.username, 'Enter your username'),
  password: checkRequired(v.password, 'Enter your password'),
}))

const { loading, run: submit } = useAsyncAction(async () => {
  await auth.login(username.value, password.value)
  await navigateTo(auth.isReseller ? '/users' : '/')
}, undefined, formApi)
</script>
