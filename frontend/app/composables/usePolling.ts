export function usePolling<T>(fetchOnce: () => Promise<T>, intervalMs = 5000, isTerminal: (v: T) => boolean = () => false) {
  const data = ref<T>()
  let timer: ReturnType<typeof setTimeout> | undefined
  let stopped = false

  async function tick() {
    try {
      data.value = await fetchOnce() as T
    }
    catch {
      // a failed poll just waits for the next one
    }
    if (stopped || (data.value !== undefined && isTerminal(data.value as T))) return
    timer = setTimeout(tick, intervalMs)
  }

  function stop() {
    stopped = true
    clearTimeout(timer)
  }

  function refresh() {
    clearTimeout(timer)
    return tick()
  }

  tick()
  onScopeDispose(stop)
  return { data, stop, refresh }
}
