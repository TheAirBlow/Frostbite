<template>
  <div class="bg-base-100 border-base-300 rounded-xl border p-3">
    <form class="grid gap-2 sm:grid-cols-12" novalidate @submit.prevent="save()">
      <FormField class="sm:col-span-3" label="Name" name="name"><input v-model="draft.name" class="input w-full" :placeholder="$t('Name')"></FormField>
      <FormField class="sm:col-span-4" label="User agent pattern" name="ua_regex" required><input v-model="draft.ua_regex" class="input w-full font-mono" :placeholder="$t('clash|mihomo')" autocomplete="off" spellcheck="false"></FormField>
      <FormField class="sm:col-span-2" label="Format" name="format"><select v-model="draft.format" class="select w-full"><option v-for="f in formats" :key="f" :value="f">{{ f }}</option></select></FormField>
      <FormField class="sm:col-span-3" label="Template" name="template_id"><select v-model="draft.template_id" class="select w-full"><option :value="null">{{ $t('No template') }}</option><option v-for="t in templates" :key="t.id" :value="t.id">{{ t.name }}</option></select></FormField>
      <FormBanner class="sm:col-span-12" />
      <div class="flex items-center justify-between gap-2 sm:col-span-12">
        <label class="flex items-center gap-2 text-sm"><input v-model="draft.enabled" type="checkbox" class="toggle toggle-xs toggle-primary"> {{ $t('Enabled') }}</label>
        <div class="flex gap-1">
          <ConfirmButton type="button" class="btn btn-ghost btn-xs text-error" confirm-label="Delete?" @confirmed="remove()"><Icon name="fa6-solid:trash" size="11" /></ConfirmButton>
          <button class="btn btn-xs btn-primary" :disabled="saving">{{ $t('Save') }}</button>
        </div>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import type { SubRule, SubTemplate } from '~/types/api'

const props = defineProps<{ rule: SubRule, templates: SubTemplate[], formats: string[] }>()
const emit = defineEmits<{ changed: [] }>()

const draft = ref<SubRule>({ ...props.rule })
watch(() => props.rule, r => (draft.value = { ...r }))

const formApi = useForm(draft, r => problems({
  ua_regex: checkRequired(r.ua_regex, 'Enter a pattern, for example clash|mihomo') ?? checkRegex(r.ua_regex),
}))

const { loading: saving, run: save } = useAsyncAction(async () => {
  await useApi(`/sub/rules/${draft.value.id}`, { method: 'PUT', body: { ...draft.value } })
  emit('changed')
}, 'Saved.', formApi)

const { run: remove } = useAsyncAction(async () => {
  await useApi(`/sub/rules/${draft.value.id}`, { method: 'DELETE' })
  emit('changed')
})
</script>
