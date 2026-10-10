import type { Admin } from '~/types/api'

export const useAuthStore = defineStore('auth', () => {
  const me = ref<Admin | null>(null)
  const ready = ref(false)
  const authed = computed(() => me.value !== null)
  const isOwner = computed(() => me.value?.role === 'owner')
  const isReseller = computed(() => me.value?.role === 'reseller')

  async function fetchMe() {
    try {
      me.value = await useApi<Admin>('/auth/me')
    }
    catch (e) {
      if (!(e instanceof ApiError) || e.status !== 401) throw e
      me.value = null
    }
    finally {
      ready.value = true
    }
  }

  async function login(username: string, password: string) {
    me.value = await useApi<Admin>('/auth/login', { method: 'POST', body: { username, password } })
  }

  async function logout() {
    await useApi('/auth/logout', { method: 'POST' })
    me.value = null
    await navigateTo('/login')
  }

  return { me, ready, authed, isOwner, isReseller, fetchMe, login, logout }
})
