<template>
  <p v-if="message" class="text-error flex items-start gap-1.5 text-xs" role="alert" :data-field="name" data-field-error>
    <Icon name="fa6-solid:circle-exclamation" size="12" class="mt-0.5 shrink-0" />
    <span>{{ t(message) }}</span>
  </p>
</template>

<script setup lang="ts">
// An error that belongs to a group of fields rather than one input, such as "a rule needs a condition".
const props = defineProps<{ name: string }>()
const { t } = useT()
const ctx = inject(formKey, null)
const message = computed(() => ctx?.error(props.name) ?? '')
</script>
