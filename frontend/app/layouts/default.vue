<template>
  <div class="bg-base-100 text-base-content relative isolate min-h-dvh sm:pl-20">
    <div class="glow pointer-events-none absolute inset-x-0 top-0 -z-10 h-[32rem]" />
    <AppNavRail />
    <main class="mx-auto max-w-[1500px] px-4 pt-5 pb-24 sm:px-6 sm:py-7">
      <slot />
    </main>
    <DrawerHost />
    <ToastHost />
  </div>
</template>

<script setup lang="ts">
useGlobalShortcuts()
</script>
