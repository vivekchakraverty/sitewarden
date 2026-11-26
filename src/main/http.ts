// Shared HTTP helpers for checks. Every request identifies itself honestly.
export const USER_AGENT = 'SiteWarden/0.1 (owner-verified security self-scan)'

export interface FetchedPage {
  url: string
  status: number
  headers: Headers
  setCookies: string[]
  body: string
}

export async function get(
  url: string,
  opts: { redirect?: RequestRedirect; timeoutMs?: number; maxBytes?: number } = {}
): Promise<FetchedPage> {
  const res = await fetch(url, {
    redirect: opts.redirect ?? 'follow',
    signal: AbortSignal.timeout(opts.timeoutMs ?? 15000),
    headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,*/*;q=0.8' }
  })
  const body = await readCapped(res, opts.maxBytes ?? 2_000_000)
  return {
    url: res.url || url,
    status: res.status,
    headers: res.headers,
    setCookies: res.headers.getSetCookie?.() ?? [],
    body
  }
}

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) return ''
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  while (total < maxBytes) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
    total += value.byteLength
  }
  await reader.cancel().catch(() => undefined)
  return Buffer.concat(chunks).subarray(0, maxBytes).toString('utf8')
}
