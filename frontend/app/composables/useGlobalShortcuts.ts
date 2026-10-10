const pages: Record<string, string> = {
  d: '/',
  u: '/users',
  n: '/nodes',
  i: '/inbounds',
  r: '/routing',
  b: '/bridges',
  a: '/access',
  s: '/subscriptions',
}

export function useGlobalShortcuts() {
  const drawer = useDrawer()
  const auth = useAuthStore()

  useEventListener(() => (import.meta.client ? window : undefined), 'keydown', (e: KeyboardEvent) => {
    if (!auth.authed) return
    const t = e.target as HTMLElement | null
    const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)

    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault()
      drawer.open('palette')
      return
    }
    if (e.metaKey || e.ctrlKey || e.altKey || e.repeat || typing) return
    if (document.querySelector('dialog[open]')) return

    if (e.key === '/') {
      e.preventDefault()
      drawer.open('palette')
      return
    }
    if (e.key === ',') {
      e.preventDefault()
      drawer.open('settings')
      return
    }
    const to = pages[e.key.toLowerCase()]
    if (to) navigateTo(to)
  })
}
