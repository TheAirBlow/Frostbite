<template>
  <div class="bg-base-100 text-base-content flex min-h-dvh flex-col items-center justify-center gap-4 p-6 text-center">
    <Icon name="fa6-solid:snowflake" size="48" class="text-primary" />
    <h1 class="font-display text-4xl font-semibold">
      {{ error?.statusCode === 404 ? 'Nothing here' : 'Something broke' }}
    </h1>
    <p class="text-base-content/60 max-w-md text-sm">
      {{ error?.statusCode === 404 ? 'That page does not exist, or it moved.' : error?.message }}
    </p>
    <button class="btn btn-primary" @click="clearError({ redirect: '/' })">
      {{ $t('Back to the dashboard') }}
    </button>
  </div>
</template>

<script setup lang="ts">
defineProps<{ error?: { statusCode?: number, message?: string } }>()
</script>
