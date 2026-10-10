export const usePreferencesStore = defineStore('preferences', () => {
  const advanced = ref(false)
  const usersSort = ref('')
  const usersPageSize = ref(50)
  const dashRange = ref('24h')
  const trafficRange = ref('7d')
  const locale = ref('')

  return { advanced, usersSort, usersPageSize, dashRange, trafficRange, locale }
}, {
  persist: {
    storage: piniaPluginPersistedstate.localStorage(),
    pick: ['advanced', 'usersSort', 'usersPageSize', 'dashRange', 'trafficRange', 'locale'],
  },
})
