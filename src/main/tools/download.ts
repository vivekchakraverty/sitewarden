// Downloads with a size cap and mandatory SHA-256 verification.
import { createHash } from 'crypto'

export const TOOLS_UA = 'SiteWarden-Desktop/0.3'

export async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: { 'User-Agent': TOOLS_UA, Accept: 'application/json' }, signal: AbortSignal.timeout(30000) })
  if (!res.ok) throw new Error(`${new URL(url).host} returned HTTP ${res.status}`)
  return (await res.json()) as T
}

export async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { headers: { 'User-Agent': TOOLS_UA }, signal: AbortSignal.timeout(30000) })
  if (!res.ok) throw new Error(`${new URL(url).host} returned HTTP ${res.status}`)
  return res.text()
}

export async function downloadVerified(
  url: string,
  sha256: string,
  opts: { maxBytes: number; onProgress?: (done: number, total: number) => void; signal?: AbortSignal }
): Promise<Buffer> {
  if (!/^[0-9a-f]{64}$/i.test(sha256)) throw new Error('Missing or malformed checksum; refusing to download.')
  const timeout = AbortSignal.timeout(15 * 60_000)
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout
  const res = await fetch(url, { headers: { 'User-Agent': TOOLS_UA }, signal })
  if (!res.ok || !res.body) throw new Error(`Download failed: HTTP ${res.status}`)
  const total = Number(res.headers.get('content-length') || 0)
  if (total > opts.maxBytes) throw new Error(`Download is larger than expected (${Math.round(total / 1e6)} MB).`)
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let done = 0
  let lastReport = 0
  for (;;) {
    const { done: end, value } = await reader.read()
    if (end) break
    done += value.byteLength
    if (done > opts.maxBytes) {
      await reader.cancel()
      throw new Error('Download exceeded the expected size; aborted.')
    }
    chunks.push(value)
    if (opts.onProgress && Date.now() - lastReport > 250) {
      lastReport = Date.now()
      opts.onProgress(done, total)
    }
  }
  const buf = Buffer.concat(chunks)
  const actual = createHash('sha256').update(buf).digest('hex')
  if (actual.toLowerCase() !== sha256.toLowerCase()) throw new Error('Checksum mismatch: the download was corrupted or tampered with. Nothing was installed.')
  return buf
}
