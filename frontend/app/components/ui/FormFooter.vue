<template>
  <!-- sticks to the bottom of the drawer's scroll area; the negative offset cancels that area's padding -->
  <div class="bg-base-100 border-base-300 sticky -bottom-4 z-10 -mx-4 -mb-4 flex flex-col gap-2 border-t p-3">
    <FormBanner />
    <div class="flex items-center justify-between gap-2">
      <slot />
    </div>
  </div>
</template>
