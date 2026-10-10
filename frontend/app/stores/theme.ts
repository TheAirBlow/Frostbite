export const useThemeStore = defineStore('theme', () => {
  const primary = ref('')

  function applyToDom() {
    if (!import.meta.client) return
    const root = document.documentElement
    if (primary.value) {
      root.style.setProperty('--color-primary', primary.value)
      root.style.setProperty('--color-primary-content', contrastOf(primary.value))
    }
    else {
      root.style.removeProperty('--color-primary')
      root.style.removeProperty('--color-primary-content')
    }
  }

  function setPrimary(color: string) {
    primary.value = color
    applyToDom()
  }

  return { primary, setPrimary, applyToDom }
}, {
  persist: { storage: piniaPluginPersistedstate.localStorage(), pick: ['primary'] },
})

// picks black or white text for a hex background
function contrastOf(hex: string): string {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex)
  if (!m) return '#000'
  const n = parseInt(m[1]!, 16)
  const lum = (0.299 * ((n >> 16) & 255) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255
  return lum > 0.6 ? '#10151f' : '#ffffff'
}
