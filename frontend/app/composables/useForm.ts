import type { InjectionKey } from 'vue'

// What a FormField needs from the form around it.
export interface FormContext {
  error: (path: string) => string
  touch: (path: string) => void
  banner: Ref<string>
}

export const formKey: InjectionKey<FormContext> = Symbol('frostbite-form')

type Rules<S> = (state: S) => Record<string, string | undefined>

// Walks a path such as options.t_routes.0.target through the form state.
function valueAt(state: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), state)
}

/**
 * Form validation that covers both sides: rules run in the browser as the person types, and whatever the
 * backend refuses lands on the same field. Field paths are the ones the API uses (security.reality.dest), so a
 * rejected request points at the input the mistake is in.
 *
 * - `rules` returns every current problem, keyed by field path. They show for a field once it was left once,
 *   and for all fields after the first submit.
 * - `fail(error)` puts a backend error on its field, or in the banner when it has none or the field is not on screen.
 * - `reveal(path)` lets tabbed forms switch to the tab that holds a field before it is focused.
 */
export function useForm<S extends object>(source: MaybeRefOrGetter<S | null | undefined>, rules?: Rules<S>, opts: { reveal?: (path: string) => void, provide?: boolean } = {}) {
  const { t } = useT()
  const attempted = ref(false)
  const touched = ref(new Set<string>())
  const server = ref<Record<string, { msg: string, value: string }>>({})
  const banner = ref('')

  const found = computed(() => {
    const out: Record<string, string> = {}
    const state = toValue(source)
    if (!state) return out
    for (const [path, msg] of Object.entries(rules?.(state) ?? {})) if (msg) out[path] = msg
    return out
  })

  const errors = computed(() => {
    const out: Record<string, string> = {}
    for (const [path, msg] of Object.entries(found.value)) {
      if (attempted.value || touched.value.has(path)) out[path] = msg
    }
    // a backend complaint lasts until the value it was about changes
    for (const [path, e] of Object.entries(server.value)) {
      if (!out[path] && JSON.stringify(valueAt(toValue(source), path) ?? null) === e.value) out[path] = e.msg
    }
    return out
  })

  const ctx: FormContext = {
    error: path => errors.value[path] ?? '',
    touch: (path) => {
      if (!touched.value.has(path)) touched.value = new Set(touched.value).add(path)
    },
    banner,
  }
  // a component with several forms turns this off and puts each one in a <FormScope>
  if (opts.provide !== false) provide(formKey, ctx)

  async function focusFirst(path?: string) {
    if (path) opts.reveal?.(path)
    await nextTick()
    await nextTick()
    if (!import.meta.client) return
    const el = document.querySelector<HTMLElement>('dialog[open] [data-field-error]') ?? document.querySelector<HTMLElement>('[data-field-error]')
    if (!el) return
    for (let p = el.parentElement; p; p = p.parentElement) {
      if (p instanceof HTMLDetailsElement && !p.open) p.open = true
    }
    await nextTick()
    const calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    el.scrollIntoView({ block: 'center', behavior: calm ? 'auto' : 'smooth' })
    el.querySelector<HTMLElement>('input:not([type=hidden]), select, textarea')?.focus({ preventScroll: true })
  }

  // Run before a submit. Shows every problem and moves to the first one.
  function validate(): boolean {
    attempted.value = true
    banner.value = ''
    const bad = Object.keys(found.value)
    if (!bad.length) return true
    banner.value = bad.length === 1 ? t('One field needs your attention.') : t('{n} fields need your attention.', { n: bad.length })
    focusFirst(bad[0])
    return false
  }

  // Clears what the last attempt left behind, before sending a new one.
  function begin() {
    banner.value = ''
    server.value = {}
  }

  // Shows a backend error where it belongs.
  function fail(e: unknown) {
    const field = e instanceof ApiError ? e.body?.field : undefined
    const message = errorMessage(e)
    if (!field) {
      banner.value = message
      return
    }
    server.value = { ...server.value, [field]: { msg: message, value: JSON.stringify(valueAt(toValue(source), field) ?? null) } }
    banner.value = ''
    focusFirst(field).then(() => {
      // a field that is not on screen (a closed section, a field the form has no input for) must not hide the error
      if (import.meta.client && !document.querySelector(`[data-field="${CSS.escape(field)}"]`)) banner.value = message
    })
  }

  // Marks a single field by hand, for checks that need the network.
  function setError(path: string, msg: string) {
    server.value = { ...server.value, [path]: { msg, value: JSON.stringify(valueAt(toValue(source), path) ?? null) } }
  }

  function reset() {
    attempted.value = false
    touched.value = new Set()
    server.value = {}
    banner.value = ''
  }

  return { ctx, errors, banner, validate, begin, fail, setError, reset, focusFirst, touch: ctx.touch, ok: computed(() => !Object.keys(found.value).length) }
}

export type FormApi = ReturnType<typeof useForm>
