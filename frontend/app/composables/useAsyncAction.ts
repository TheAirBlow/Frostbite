import type { FormApi } from './useForm'

// Runs an async action with a loading flag and a toast for the outcome.
// Given a form, the action validates it first and shows backend errors on their fields instead of a toast.
export function useAsyncAction<A extends unknown[], R>(fn: (...args: A) => Promise<R>, successMessage?: string, form?: FormApi) {
  const toast = useToast()
  const loading = ref(false)

  async function run(...args: A): Promise<R | undefined> {
    if (form && !form.validate()) return
    form?.begin()
    loading.value = true
    try {
      const result = await fn(...args)
      if (successMessage) toast.success(successMessage)
      return result
    }
    catch (e) {
      if (form) form.fail(e)
      else toast.error(errorMessage(e))
    }
    finally {
      loading.value = false
    }
  }

  return { loading, run }
}
