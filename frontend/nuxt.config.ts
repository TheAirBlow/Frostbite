import tailwindcss from '@tailwindcss/vite'

// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: false },
  ssr: true,

  app: {
    head: {
      titleTemplate: '%s · Frostbite',
      title: 'Frostbite',
      meta: [
        { name: 'description', content: 'Manage your VPN nodes, bridges and users.' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1, viewport-fit=cover' },
        { name: 'robots', content: 'noindex' },
      ],
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    },
    pageTransition: { name: 'fade', mode: 'out-in' },
  },

  modules: [
    '@pinia/nuxt',
    'pinia-plugin-persistedstate/nuxt',
    '@nuxtjs/color-mode',
    '@vueuse/nuxt',
    '@nuxt/icon',
    '@nuxt/eslint',
    'nuxt-charts',
  ],

  components: [{ path: '~/components', pathPrefix: false }],

  css: ['~/assets/css/main.css'],
  vite: { plugins: [tailwindcss()] },

  colorMode: {
    classSuffix: '',
    dataValue: 'theme',
    preference: 'frostbite',
    fallback: 'frostbite',
  },

  icon: {
    mode: 'svg',
    class: 'app-icon',
    clientBundle: {
      scan: true,
      sizeLimitKb: 512,
    },
  },

  nitro: {
    compressPublicAssets: true,
    // daemons keep a websocket open at /api/link, see server/routes/api/link.ts
    experimental: { websocket: true },
    routeRules: {
      // only the self service page is rendered on the server, the admin screens need a signed in browser
      '/**': { ssr: false },
      '/u/**': { ssr: true, headers: { 'cache-control': 'no-store' } },
      '/api/**': { headers: { 'cache-control': 'no-store' } },
    },
  },

  runtimeConfig: {
    // where the panel listens, only this server talks to it
    backendUrl: 'http://127.0.0.1:8080',
  },
})
