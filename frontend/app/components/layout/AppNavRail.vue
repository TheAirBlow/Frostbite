<template>
  <!-- mobile: bottom tab bar -->
  <nav
    class="bg-base-200/95 border-base-300 fixed inset-x-0 bottom-0 z-40 grid border-t backdrop-blur transition-transform duration-200 pb-[env(safe-area-inset-bottom)] sm:hidden"
    :class="hidden ? 'translate-y-[calc(100%_+_1px)]' : ''"
    :style="{ gridTemplateColumns: `repeat(${mobileMain.length + 1}, minmax(0, 1fr))` }"
  >
    <NuxtLink v-for="item in mobileMain" :key="item.to" :to="item.to" :class="tab" active-class="text-primary" exact-active-class="text-primary">
      <Icon :name="item.icon" size="18" />
      <span class="max-w-full truncate px-0.5">{{ t(item.key) }}</span>
    </NuxtLink>
    <div class="dropdown dropdown-top dropdown-end">
      <button tabindex="0" :class="[tab, 'w-full']">
        <Icon name="fa6-solid:ellipsis" size="18" />
        {{ t('nav.more') }}
      </button>
      <ul tabindex="0" class="dropdown-content menu bg-base-200 border-base-300 rounded-box z-50 mb-2 w-52 border p-2 shadow-xl">
        <li v-for="item in mobileMore" :key="item.to">
          <NuxtLink :to="item.to"><Icon :name="item.icon" size="14" /> {{ t(item.key) }}</NuxtLink>
        </li>
        <li><button @click="drawer.open('settings')"><Icon name="fa6-solid:gear" size="14" /> {{ t('nav.settings') }}</button></li>
        <li><button class="text-error" @click="auth.logout()"><Icon name="fa6-solid:right-from-bracket" size="14" /> {{ t('nav.signout') }}</button></li>
      </ul>
    </div>
  </nav>

  <!-- desktop: left rail -->
  <nav class="bg-base-200 border-base-300 fixed top-0 left-0 z-40 hidden h-dvh w-20 flex-col justify-between border-r py-4 sm:flex">
    <div class="flex flex-col items-center gap-1.5">
      <NuxtLink to="/" class="mb-3 grid size-11 place-items-center rounded-2xl bg-gradient-to-br from-primary/90 to-secondary/90 text-primary-content shadow-lg shadow-primary/20">
        <Icon name="fa6-solid:snowflake" size="22" />
      </NuxtLink>
      <NavKbdTooltip v-for="item in items" :key="item.to" :label="t(item.key)" :kbd="item.kbd">
        <NuxtLink :to="item.to" :class="rail" active-class="bg-primary/15! text-primary!" :exact-active-class="item.to === '/' ? 'bg-primary/15! text-primary!' : ''">
          <Icon :name="item.icon" size="19" />
        </NuxtLink>
      </NavKbdTooltip>
    </div>
    <div class="flex flex-col items-center gap-1.5">
      <NavKbdTooltip :label="t('nav.search')" kbd="/">
        <button :class="rail" @click="drawer.open('palette')"><Icon name="fa6-solid:magnifying-glass" size="17" /></button>
      </NavKbdTooltip>
      <NavKbdTooltip :label="t('nav.settings')" kbd=",">
        <button :class="rail" @click="drawer.open('settings')"><Icon name="fa6-solid:gear" size="18" /></button>
      </NavKbdTooltip>
      <NavKbdTooltip :label="`${t('nav.signout')} ${auth.me?.username ?? ''}`">
        <button :class="rail" @click="auth.logout()"><Icon name="fa6-solid:right-from-bracket" size="17" /></button>
      </NavKbdTooltip>
    </div>
  </nav>
</template>

<script setup lang="ts">
const auth = useAuthStore()
const drawer = useDrawer()
const { t } = useT()

interface NavItem { to: string, key: string, icon: string, kbd?: string }

const all: NavItem[] = [
  { to: '/', key: 'nav.dashboard', icon: 'fa6-solid:chart-line', kbd: 'D' },
  { to: '/users', key: 'nav.users', icon: 'fa6-solid:users', kbd: 'U' },
  { to: '/nodes', key: 'nav.nodes', icon: 'fa6-solid:server', kbd: 'N' },
  { to: '/inbounds', key: 'nav.inbounds', icon: 'fa6-solid:plug', kbd: 'I' },
  { to: '/routing', key: 'nav.routing', icon: 'fa6-solid:route', kbd: 'R' },
  { to: '/bridges', key: 'nav.bridges', icon: 'fa6-solid:bridge', kbd: 'B' },
  { to: '/access', key: 'nav.access', icon: 'fa6-solid:layer-group', kbd: 'A' },
  { to: '/subscriptions', key: 'nav.subscriptions', icon: 'fa6-solid:rss', kbd: 'S' },
]

const items = computed(() => (auth.isReseller ? all.filter(i => i.to === '/users') : all))
const mobileMain = computed(() => items.value.slice(0, 4))
const mobileMore = computed(() => items.value.slice(4))

const rail = 'text-base-content/60 hover:bg-base-300 hover:text-base-content grid size-11 place-items-center rounded-2xl transition-colors'
const tab = 'flex flex-col items-center justify-center gap-1.5 py-2.5 text-[12px] leading-none transition-colors text-base-content/70'

const hidden = ref(false)
let lastY = 0
useEventListener(() => (import.meta.client ? window : undefined), 'scroll', () => {
  const y = window.scrollY
  hidden.value = y > lastY && y > 80
  lastY = y
}, { passive: true })
</script>
