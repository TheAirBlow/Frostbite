import type { Admin } from '~/types/api'

export const useAuthStore = defineStore('auth', () => {
  const me = ref<Admin | null>(null)
  const ready = ref(false)
  const authed = computed(() => me.value !== null)
  const isOwner = computed(() => me.value?.role === 'owner')
  const isReseller = computed(() => me.value?.role === 'reseller')
  const isNodeAdmin = computed(() => me.value?.role === 'node_admin')
  // pages the role may open, null for all of them
  const pages = computed<string[] | null>(() => {
    if (isReseller.value) return ['/users']
    if (isNodeAdmin.value) return ['/users', '/nodes', '/inbounds', '/routing', '/bridges', '/access']
    return null
  })
  const canVisit = (path: string) => !pages.value || pages.value.includes(path)
  const home = computed(() => pages.value?.[0] ?? '/')

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

  return { me, ready, authed, isOwner, isReseller, isNodeAdmin, canVisit, home, fetchMe, login, logout }
})
