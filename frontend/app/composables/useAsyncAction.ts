export function useAsyncAction<A extends unknown[], R>(fn: (...args: A) => Promise<R>, successMessage?: string) {
  const toast = useToast()
  const loading = ref(false)

  async function run(...args: A): Promise<R | undefined> {
    loading.value = true
    try {
      const result = await fn(...args)
      if (successMessage) toast.success(successMessage)
      return result
    }
    catch (e) {
      toast.error(errorMessage(e))
    }
    finally {
      loading.value = false
    }
  }

  return { loading, run }
}
