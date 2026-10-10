<template>
  <div class="flex min-h-dvh items-center justify-center p-4">
    <form class="surface w-full max-w-sm p-7 shadow-2xl" @submit.prevent="submit">
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
        <FormField :label="t('login.username')">
          <input v-model="username" class="input w-full" autocomplete="username" autofocus required>
        </FormField>
        <FormField :label="t('login.password')">
          <input v-model="password" type="password" class="input w-full" autocomplete="current-password" required>
        </FormField>
      </div>

      <p v-if="error" class="text-error mt-3 text-sm">{{ error }}</p>

      <button class="btn btn-primary mt-5 w-full" :class="{ 'btn-disabled': loading }">
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
const error = ref('')
const loading = ref(false)

async function submit() {
  loading.value = true
  error.value = ''
  try {
    await auth.login(username.value, password.value)
    await navigateTo(auth.isReseller ? '/users' : '/')
  }
  catch (e) {
    error.value = errorMessage(e)
  }
  finally {
    loading.value = false
  }
}
</script>
