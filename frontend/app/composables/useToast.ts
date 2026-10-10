export interface Toast {
  id: number
  type: 'success' | 'error' | 'info'
  message: string
}

let nextId = 1

export function useToast() {
  const toasts = useState<Toast[]>('toasts', () => [])
  const { t: translate } = useT()

  function dismiss(id: number) {
    toasts.value = toasts.value.filter(t => t.id !== id)
  }

  function push(type: Toast['type'], message: string) {
    const id = nextId++
    toasts.value = [...toasts.value, { id, type, message: translate(message) }]
    setTimeout(() => dismiss(id), type === 'error' ? 6000 : 3500)
  }

  return {
    toasts,
    dismiss,
    success: (m: string) => push('success', m),
    error: (m: string) => push('error', m),
    info: (m: string) => push('info', m),
  }
}
