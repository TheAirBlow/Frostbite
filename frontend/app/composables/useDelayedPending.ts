// Keeps skeletons from flashing: show only after a short delay, and once shown keep them a moment.
export function useDelayedPending(pending: Ref<boolean>, showDelay = 250, minVisible = 300) {
  const shown = ref(false)
  let showTimer: ReturnType<typeof setTimeout> | undefined
  let shownAt = 0

  watch(pending, (p) => {
    clearTimeout(showTimer)
    if (p) {
      showTimer = setTimeout(() => {
        shown.value = true
        shownAt = Date.now()
      }, showDelay)
      return
    }
    if (!shown.value) return
    const left = Math.max(0, minVisible - (Date.now() - shownAt))
    showTimer = setTimeout(() => (shown.value = false), left)
  }, { immediate: true })

  onScopeDispose(() => clearTimeout(showTimer))
  return shown
}
