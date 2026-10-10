export type PanelName = 'settings' | 'user-create' | 'user-batch' | 'user-import' | 'bridge' | 'palette'

export function useDrawer() {
  const route = useRoute()
  const router = useRouter()

  const current = computed(() => (route.query.panel as PanelName | undefined) ?? null)

  function open(panel: PanelName, params: Record<string, string> = {}) {
    router.replace({ query: { ...route.query, panel, ...params } })
  }

  function close() {
    const { panel: _p, tab: _t, ...rest } = route.query
    router.replace({ query: rest })
  }

  return { current, open, close }
}
