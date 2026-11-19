<template>
  <NuxtLoadingIndicator color="var(--color-primary)" />
  <NuxtLayout>
    <NuxtPage />
  </NuxtLayout>
</template>

<script setup lang="ts">
const { locale, rtl, tag } = useT()

watchEffect(() => setFormatLocale(tag.value))
useHead({
  htmlAttrs: { lang: locale, dir: computed(() => (rtl.value ? 'rtl' : 'ltr')) },
  titleTemplate: title => (title && title !== 'Frostbite' ? `${title} · Frostbite` : 'Frostbite'),
})
</script>
