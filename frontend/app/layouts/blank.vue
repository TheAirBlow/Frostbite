<template>
  <div class="bg-base-100 text-base-content relative isolate min-h-dvh">
    <div class="glow pointer-events-none absolute inset-x-0 top-0 -z-10 h-[40rem]" />
    <slot />
    <ToastHost />
  </div>
</template>
