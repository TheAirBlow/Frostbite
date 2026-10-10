export default defineNuxtRouteMiddleware((to) => {
  if (to.path.startsWith('/u/')) return
  const auth = useAuthStore()
  if (to.path === '/login') {
    if (auth.authed) return navigateTo('/')
    return
  }
  if (!auth.authed) return navigateTo('/login')
  if (auth.isReseller && !['/users'].includes(to.path)) return navigateTo('/users')
})
