<template>
  <slot />
</template>

<script setup lang="ts">
import type { FormApi } from '~/composables/useForm'

// Hands one form's errors to the fields inside it. A component with a single useForm does not need this,
// useForm already provides itself. Use it when one component holds several forms (useForm(..., { provide: false })).
const props = defineProps<{ form: FormApi }>()
provide(formKey, {
  error: path => props.form.ctx.error(path),
  touch: path => props.form.ctx.touch(path),
  banner: computed(() => props.form.ctx.banner.value),
})
</script>
