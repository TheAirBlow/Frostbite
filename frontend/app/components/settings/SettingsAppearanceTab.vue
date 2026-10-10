<template>
  <div class="flex max-w-3xl flex-col gap-5">
    <Section :title="$t('Theme')">
      <div class="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
        <button v-for="t in themes" :key="t" class="bg-base-100 border-base-300 hover:border-primary/60 overflow-hidden rounded-xl border text-left transition" :class="{ 'border-primary ring-primary/40 ring-1': colorMode.preference === t }" :data-theme="t" @click="colorMode.preference = t">
          <div class="bg-base-100 text-base-content p-2.5">
            <div class="mb-1.5 flex gap-1"><span class="bg-primary size-3 rounded-full" /><span class="bg-secondary size-3 rounded-full" /><span class="bg-accent size-3 rounded-full" /><span class="bg-neutral size-3 rounded-full" /></div>
            <p class="text-xs font-medium capitalize">{{ t }}</p>
          </div>
        </button>
      </div>
    </Section>

    <Section :title="$t('Accent colour')" hint="Overrides the theme's primary colour on this device.">
      <div class="flex flex-wrap items-center gap-3">
        <input type="color" class="size-10 cursor-pointer rounded-lg border-0 bg-transparent" :value="theme.primary || '#7cc8f7'" @input="theme.setPrimary(($event.target as HTMLInputElement).value)">
        <div class="flex gap-1.5"><button v-for="c in swatches" :key="c" class="size-7 rounded-full border border-white/20" :style="{ background: c }" :aria-label="c" @click="theme.setPrimary(c)" /></div>
        <button v-if="theme.primary" class="btn btn-ghost btn-sm" @click="theme.setPrimary('')">{{ $t('Reset') }}</button>
      </div>
    </Section>

    <Section :title="$t('Interface')">
      <FormField label="Language"><LanguageSwitcher align="dropdown-start" /></FormField>
      <ToggleRow v-model="prefs.advanced" label="Advanced mode" hint="Shows every knob: raw patches, listen addresses, sort orders, fragment settings and more. Off hides them to keep forms short." />
      <FormField label="Users per page"><select v-model.number="prefs.usersPageSize" class="select w-32"><option v-for="n in [25, 50, 100, 200]" :key="n" :value="n">{{ n }}</option></select></FormField>
    </Section>

    <Section :title="$t('Keyboard')">
      <dl class="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm sm:grid-cols-3">
        <template v-for="k in keys" :key="k[0]"><dt><kbd class="kbd kbd-sm">{{ k[0] }}</kbd></dt><dd class="text-base-content/70 sm:col-span-2">{{ k[1] }}</dd></template>
      </dl>
    </Section>
  </div>
</template>

<script setup lang="ts">
const colorMode = useColorMode()
const theme = useThemeStore()
const prefs = usePreferencesStore()

const themes = ['frostbite', 'frost', 'light', 'dark', 'dracula', 'nord', 'night', 'business', 'synthwave', 'forest', 'luxury', 'cupcake', 'emerald', 'corporate', 'lofi', 'winter', 'dim', 'sunset', 'black', 'abyss', 'silk']
const swatches = ['#7cc8f7', '#a78bfa', '#34d399', '#f59e0b', '#fb7185', '#38bdf8', '#e879f9']
const keys = [['/ or Ctrl K', 'Search and jump'], ['D', 'Dashboard'], ['U', 'Users'], ['N', 'Nodes'], ['I', 'Inbounds'], ['R', 'Routing'], ['B', 'Bridges'], ['A', 'Squads & plans'], ['S', 'Subscriptions'], [',', 'Settings'], ['Esc', 'Close a panel']]
</script>
