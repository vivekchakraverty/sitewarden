// Minimal Cloudflare v4 API client using the user's own API token.
const BASE = 'https://api.cloudflare.com/client/v4'

export class CfError extends Error {
  constructor(
    message: string,
    public status: number,
    public codes: number[]
  ) {
    super(message)
  }
}

interface Envelope<T> {
  success: boolean
  result: T
  errors?: { code: number; message: string }[]
  result_info?: { page: number; total_pages: number }
}

export async function cf<T>(
  token: string,
  method: string,
  path: string,
  body?: unknown,
  opts: { form?: FormData; timeoutMs?: number } = {}
): Promise<T> {
  const headers: Record<string, string> = { Authorization: `Bearer ${token}` }
  let payload: BodyInit | undefined
  if (opts.form) payload = opts.form
  else if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  const res = await fetch(`${BASE}${path}`, { method, headers, body: payload, signal: AbortSignal.timeout(opts.timeoutMs ?? 30000) })
  let data: Envelope<T> | undefined
  try {
    data = (await res.json()) as Envelope<T>
  } catch {
    // non-JSON error page
  }
  if (!res.ok || !data?.success) {
    const errs = data?.errors ?? []
    const msg = errs.map((e) => `${e.message} (${e.code})`).join('; ') || `HTTP ${res.status}`
    const hint = res.status === 403 || errs.some((e) => e.code === 10000 || e.code === 9109) ? ' — the API token is missing a permission for this.' : ''
    throw new CfError(`${msg}${hint}`, res.status, errs.map((e) => e.code))
  }
  return data.result
}

/** Fetches every page of a list endpoint. */
export async function cfAll<T>(token: string, path: string): Promise<T[]> {
  const out: T[] = []
  for (let page = 1; page < 50; page++) {
    const sep = path.includes('?') ? '&' : '?'
    const res = await fetch(`${BASE}${path}${sep}page=${page}&per_page=50`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(30000)
    })
    const data = (await res.json()) as Envelope<T[]>
    if (!res.ok || !data.success) {
      throw new CfError(data.errors?.map((e) => e.message).join('; ') || `HTTP ${res.status}`, res.status, data.errors?.map((e) => e.code) ?? [])
    }
    out.push(...data.result)
    if (!data.result_info || page >= data.result_info.total_pages) break
  }
  return out
}
