<template>
  <form v-if="form" class="flex max-w-3xl flex-col gap-5" novalidate @submit.prevent="save()">
    <Section :title="$t('Telegram')" hint="Alerts for admins, and optionally for users who linked their account.">
      <div class="flex flex-col gap-3">
        <ToggleRow v-model="form.telegram.enabled" label="Enable the bot" hint="Create a bot with @BotFather and paste its token. It answers /usage and /link for users and has admin commands for the chats below." />
        <template v-if="form.telegram.enabled">
          <FormField label="Bot token" name="telegram.token" :hint="form.token_set ? 'A token is saved. Leave empty to keep it.' : ''"><input v-model="form.telegram.token" type="password" class="input w-full font-mono" autocomplete="off" :placeholder="form.token_set ? '••••••••' : '123456:ABC…'"></FormField>
          <FormField label="Admin chat ids" name="telegram.admin_ids" hint="Numeric ids. Message the bot and send /start to see yours.">
            <ChipInput :model-value="form.telegram.admin_ids.map(String)" placeholder="123456789" :check="checkChatId" @update:model-value="form.telegram.admin_ids = $event.map(Number)" />
          </FormField>
          <ToggleRow v-model="form.telegram.notify_users" label="Also message users" hint="Users who opened the Telegram link on their subscription page hear about expiry and usage themselves." />
          <EventPicker v-model="form.telegram.events" label="Admin alerts" />
          <Advanced><FormField label="API address" name="telegram.api_base" hint="Only for self hosted bot api servers or a proxy."><input v-model="form.telegram.api_base" class="input w-full font-mono" :placeholder="$t('https://api.telegram.org')"></FormField></Advanced>
        </template>
      </div>
    </Section>

    <Section :title="$t('Webhooks')" hint="Frostbite POSTs a json event to each address. With a secret, X-Frostbite-Signature carries an HMAC-SHA256 of the body.">
      <template #actions><button type="button" class="btn btn-sm" @click="form.webhooks.push({ url: '', secret: '', events: [], enabled: true })"><Icon name="fa6-solid:plus" size="12" /> {{ $t('Add') }}</button></template>
      <div class="flex flex-col gap-3">
        <div v-for="(h, i) in form.webhooks" :key="i" class="bg-base-100 border-base-300 rounded-xl border p-3">
          <div class="flex items-center gap-2">
            <FormField class="flex-1" label="Address" :name="`webhooks.${i}.url`" required>
              <input v-model="h.url" class="input w-full font-mono" :placeholder="$t('https://example.com/hook')" autocomplete="off">
            </FormField>
            <input v-model="h.enabled" type="checkbox" class="toggle toggle-sm toggle-primary" :aria-label="$t('Enabled')">
            <button type="button" class="btn btn-ghost btn-xs text-error" :aria-label="$t('Remove')" @click="form.webhooks.splice(i, 1)"><Icon name="fa6-solid:trash" size="12" /></button>
          </div>
          <div class="mt-2 grid gap-2">
            <FormField label="Secret" :name="`webhooks.${i}.secret`"><input v-model="h.secret" class="input w-full font-mono" :placeholder="$t('optional')"></FormField>
            <EventPicker v-model="h.events" label="Events" />
          </div>
        </div>
        <p v-if="!form.webhooks.length" class="text-base-content/50 text-sm">{{ $t('No webhooks.') }}</p>
      </div>
    </Section>

    <Section :title="$t('When to warn')">
      <div class="grid gap-3 sm:grid-cols-2">
        <FormField label="Before expiry (days)" name="expire_days" hint="One alert for each, at most. 1 to 15."><ChipInput :model-value="form.expire_days.map(String)" :check="checkDays" @update:model-value="form.expire_days = nums($event)" /></FormField>
        <FormField label="At traffic usage (%)" name="usage_percent" hint="1 to 99."><ChipInput :model-value="form.usage_percent.map(String)" :check="checkPercent" @update:model-value="form.usage_percent = nums($event)" /></FormField>
      </div>
    </Section>

    <div v-if="results" class="surface p-3">
      <p class="mb-1 text-sm font-medium">{{ $t('Test result') }}</p>
      <p v-if="!results.length" class="text-base-content/60 text-sm">{{ $t('There is nothing to send to yet. Save a target first.') }}</p>
      <ul class="text-sm"><li v-for="r in results" :key="r.target" class="flex items-center gap-2"><Icon :name="r.ok ? 'fa6-solid:circle-check' : 'fa6-solid:circle-xmark'" size="13" :class="r.ok ? 'text-success' : 'text-error'" /><span class="font-mono text-xs">{{ r.target }}</span><span v-if="r.error" class="text-error text-xs">{{ r.error }}</span></li></ul>
    </div>

    <FormBanner />
    <div class="flex justify-end gap-2">
      <button type="button" class="btn" :disabled="testing" @click="test()"><span v-if="testing" class="loading loading-spinner loading-xs" /> {{ $t('Send a test') }}</button>
      <button class="btn btn-primary" :disabled="saving">{{ $t('Save') }}</button>
    </div>
  </form>
  <Skeleton v-else :rows="4" :height="80" />
</template>

<script setup lang="ts">
import type { DeliveryResult, NotificationSettings } from '~/types/api'

const form = ref<NotificationSettings | null>(null)
const results = ref<DeliveryResult[] | null>(null)

onMounted(async () => {
  form.value = await useApi<NotificationSettings>('/settings/notifications')
})

function nums(list: string[]): number[] {
  return list.map(Number).filter(n => Number.isFinite(n) && n > 0)
}

const checkChatId = (v: string) => (/^-?\d{5,}$/.test(v) ? undefined : 'A chat id is a whole number')
const checkDays = (v: string) => checkInt(v, 1, 15, 'a number of days')
const checkPercent = (v: string) => checkInt(v, 1, 99, 'a percentage')

const formApi = useForm(form, (f) => {
  const e: Record<string, Check> = {}
  if (f.telegram.enabled) {
    if (f.telegram.token) e['telegram.token'] = /^\d+:[\w-]{20,}$/.test(f.telegram.token) ? undefined : 'A bot token looks like 123456:ABC-DEF…'
    else if (!f.token_set) e['telegram.token'] = 'Paste the token @BotFather gave you'
    if (f.telegram.api_base) e['telegram.api_base'] = checkUrl(f.telegram.api_base)
  }
  f.webhooks.forEach((h, i) => {
    e[`webhooks.${i}.url`] = checkRequired(h.url, 'Enter the address to post to') ?? checkUrl(h.url)
  })
  return problems(e)
})

const { loading: saving, run: save } = useAsyncAction(async () => {
  form.value = await useApi<NotificationSettings>('/settings/notifications', { method: 'PUT', body: { ...form.value } })
}, 'Saved.', formApi)

const { loading: testing, run: test } = useAsyncAction(async () => {
  results.value = await useApi<DeliveryResult[]>('/settings/notifications/test', { method: 'POST' })
})
</script>
