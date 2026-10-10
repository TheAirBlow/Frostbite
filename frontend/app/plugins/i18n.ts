// Templates use $t('English text'). The English text is the key, so a missing translation shows the English itself.
export default defineNuxtPlugin((nuxtApp) => {
  const { t } = useT()
  nuxtApp.vueApp.config.globalProperties.$t = (key: string | undefined, params?: Record<string, string | number>) => t(key, params)
})

declare module 'vue' {
  interface ComponentCustomProperties {
    $t: (key: string | undefined, params?: Record<string, string | number>) => string
  }
}
