import en from '~/locales/en'
import ru from '~/locales/ru'
import fa from '~/locales/fa'
import zh from '~/locales/zh'
import adminRu from '~/locales/admin/ru'
import adminFa from '~/locales/admin/fa'
import adminZh from '~/locales/admin/zh'

type Messages = Record<string, string>

export const locales: Record<string, { messages: Messages, tag: string, rtl: boolean }> = {
  en: { messages: en, tag: 'en-GB', rtl: false },
  ru: { messages: { ...ru, ...adminRu }, tag: 'ru-RU', rtl: false },
  fa: { messages: { ...fa, ...adminFa }, tag: 'fa-IR', rtl: true },
  zh: { messages: { ...zh, ...adminZh }, tag: 'zh-CN', rtl: false },
}

// picks the closest supported language for a browser's preference
export function detectLocale(): string {
  const wanted = import.meta.client ? navigator.languages ?? [navigator.language] : []
  for (const w of wanted) {
    const code = w.toLowerCase().split('-')[0]!
    if (locales[code]) return code
  }
  return 'en'
}

export function useT() {
  const prefs = usePreferencesStore()
  const locale = computed(() => (prefs.locale && locales[prefs.locale] ? prefs.locale : detectLocale()))
  const current = computed(() => locales[locale.value]!)

  // {name} placeholders, and {n} picks a plural form from key_one / key_few / key_many / key_other
  function t(key: string | undefined, params: Record<string, string | number> = {}): string {
    if (!key) return ''
    let msg: string | undefined
    if (typeof params.n === 'number') {
      const form = new Intl.PluralRules(current.value.tag).select(params.n)
      msg = current.value.messages[`${key}_${form}`] ?? current.value.messages[`${key}_other`]
    }
    msg ??= current.value.messages[key] ?? en[key as keyof typeof en] ?? key
    return msg.replace(/\{(\w+)\}/g, (_, k: string) => String(params[k] ?? ''))
  }

  function setLocale(code: string) {
    prefs.locale = code
  }

  return { t, locale, setLocale, rtl: computed(() => current.value.rtl), tag: computed(() => current.value.tag) }
}
