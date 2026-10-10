import type { ApiErrorBody } from '~/types/api'

export class ApiError extends Error {
  status: number
  body?: ApiErrorBody

  constructor(status: number, message: string, body?: ApiErrorBody) {
    super(message)
    this.status = status
    this.body = body
  }
}

interface ApiOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  query?: Record<string, unknown>
  body?: Record<string, unknown> | unknown[]
}

export async function useApi<T>(path: string, opts: ApiOptions = {}): Promise<T> {
  try {
    return await $fetch<T>(path, {
      baseURL: '/api',
      method: opts.method ?? 'GET',
      query: opts.query,
      body: opts.body,
      credentials: 'include',
    })
  }
  catch (e) {
    const err = e as { statusCode?: number, status?: number, data?: ApiErrorBody, message: string }
    const status = err.statusCode ?? err.status ?? 0
    if (status === 401 && !path.startsWith('/auth/')) {
      useAuthStore().me = null
      await navigateTo('/login')
    }
    throw new ApiError(status, err.data?.detail ?? err.message, err.data)
  }
}

export function errorMessage(e: unknown): string {
  const { t } = useT()
  if (e instanceof ApiError) return e.body?.detail ?? e.message
  return t('Something went wrong.')
}
