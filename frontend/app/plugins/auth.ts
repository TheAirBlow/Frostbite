export default defineNuxtPlugin(async () => {
  const auth = useAuthStore()
  const path = useRoute().path
  // the self service page is public and must not poke the admin api
  if (path.startsWith('/u/')) {
    auth.ready = true
    return
  }
  if (!auth.ready) await auth.fetchMe()
})
