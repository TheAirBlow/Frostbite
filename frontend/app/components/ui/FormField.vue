<template>
  <fieldset
    class="fieldset min-w-0"
    :data-field="name || undefined"
    :data-invalid="message ? '' : undefined"
    :data-field-error="message ? '' : undefined"
    @focusout="name && ctx?.touch(name)"
  >
    <legend class="fieldset-legend flex items-center gap-2">
      {{ t(label) }}
      <span v-if="required" class="text-error" aria-hidden="true">*</span>
      <span v-if="badge" class="badge badge-xs badge-ghost">{{ t(badge) }}</span>
    </legend>
    <slot />
    <p v-if="message" class="text-error flex items-start gap-1.5 text-xs" role="alert">
      <Icon name="fa6-solid:circle-exclamation" size="12" class="mt-0.5 shrink-0" />
      <span>{{ t(message) }}</span>
    </p>
    <p v-if="hint" class="text-base-content/60 text-xs">{{ t(hint) }}</p>
  </fieldset>
</template>

<script setup lang="ts">
// `name` is the field's path in the API body. It ties the field to errors from the rules and from the backend.
const props = defineProps<{ label: string, hint?: string, badge?: string, name?: string, error?: string, required?: boolean }>()
const { t } = useT()
const ctx = inject(formKey, null)
const message = computed(() => props.error || (props.name ? ctx?.error(props.name) : '') || '')
</script>
