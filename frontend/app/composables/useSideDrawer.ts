export type SideDrawerKind = 'user' | 'node' | 'daemon' | 'inbound' | 'outbound' | 'rule' | 'squad' | 'plan'

export function useSideDrawer() {
  const route = useRoute()
  const router = useRouter()

  const kind = computed(() => (route.query.drawer as SideDrawerKind | undefined) ?? null)
  const id = computed(() => {
    const n = Number(route.query.id)
    return Number.isFinite(n) && n > 0 ? n : null
  })
  const isOpen = computed(() => kind.value !== null)

  // extra carries context a drawer needs when creating, such as the daemon a new inbound belongs to
  function open(k: SideDrawerKind, itemId?: number | null, extra: Record<string, string> = {}) {
    const { drawer: _d, id: _i, ...rest } = route.query
    router.replace({ query: { ...rest, drawer: k, ...(itemId ? { id: String(itemId) } : {}), ...extra } })
  }

  function close() {
    const { drawer: _d, id: _i, dtab: _t, daemon: _dm, node: _n, ...rest } = route.query
    router.replace({ query: rest })
  }

  return { kind, id, isOpen, open, close }
}
