<template>
  <div class="dropdown" :class="align">
    <button tabindex="0" class="btn btn-ghost btn-sm gap-2" :aria-label="t('portal.language')">
      <Icon name="fa6-solid:globe" size="13" /> {{ locales[locale]!.messages['lang.name'] }}
    </button>
    <ul tabindex="0" class="dropdown-content menu bg-base-200 border-base-300 rounded-box z-50 mt-1 w-44 border p-2 shadow-xl">
      <li v-for="(l, code) in locales" :key="code">
        <button :class="{ 'menu-active': locale === code }" @click="setLocale(code as string)">{{ l.messages['lang.name'] }}</button>
      </li>
    </ul>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ align?: string }>(), { align: 'dropdown-end' })
const { t, locale, setLocale } = useT()
</script>
