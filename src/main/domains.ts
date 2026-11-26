// Domain registration and ownership verification.
// Scans only run against domains the user has proved they control.
import { randomBytes, randomUUID } from 'crypto'
import { promises as dns } from 'dns'
import { isIP } from 'net'
import type { Domain, VerifyOutcome } from '../shared/types'
import { store } from './store'
import { get } from './http'

export const TXT_PREFIX = 'sitewarden-verification='
export const META_NAME = 'sitewarden-verification'
/** Re-check ownership before scanning if the last verification is older than this. */
const REVERIFY_AFTER_MS = 30 * 24 * 60 * 60 * 1000

export function normalizeHost(input: string): string {
  let s = input.trim().toLowerCase()
  if (!s) throw new Error('Enter a domain such as example.com')
  if (!/^[a-z]+:\/\//.test(s)) s = `https://${s}`
  let host: string
  try {
    host = new URL(s).hostname
  } catch {
    throw new Error('That does not look like a domain.')
  }
  host = host.replace(/\.$/, '')
  if (isIP(host) || host.startsWith('[')) throw new Error('Use a domain name, not an IP address.')
  if (host === 'localhost' || host.endsWith('.localhost') || !host.includes('.')) {
    throw new Error('Use a public domain name.')
  }
  if (!/^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/.test(host) || /(^|\.)-|-(\.|$)/.test(host)) {
    throw new Error('That does not look like a valid domain name.')
  }
  return host
}

export function addDomain(input: string): Domain {
  const host = normalizeHost(input)
  const existing = store.domains().find((d) => d.host === host)
  if (existing) return existing
  const d: Domain = {
    id: randomUUID(),
    host,
    addedAt: new Date().toISOString(),
    verificationToken: randomBytes(16).toString('hex'),
    verified: false
  }
  store.upsertDomain(d)
  return d
}

async function checkDns(d: Domain): Promise<boolean> {
  const expected = `${TXT_PREFIX}${d.verificationToken}`
  for (const name of [d.host, `_sitewarden.${d.host}`]) {
    try {
      const records = await dns.resolveTxt(name)
      if (records.some((parts) => parts.join('').trim() === expected)) return true
    } catch {
      // NXDOMAIN / no TXT records: try the next name
    }
  }
  return false
}

async function checkMeta(d: Domain): Promise<boolean> {
  try {
    const page = await get(`https://${d.host}/`, { timeoutMs: 12000 })
    // Only accept the tag if we ended up on the same host (or www.) to stop redirect tricks.
    const finalHost = new URL(page.url).hostname
    if (finalHost !== d.host && finalHost !== `www.${d.host}` && `www.${finalHost}` !== d.host) return false
    const metas = page.body.match(/<meta\b[^>]*>/gi) ?? []
    return metas.some(
      (m) =>
        new RegExp(`name\\s*=\\s*["']${META_NAME}["']`, 'i').test(m) &&
        new RegExp(`content\\s*=\\s*["']${d.verificationToken}["']`, 'i').test(m)
    )
  } catch {
    return false
  }
}

export async function verifyDomain(id: string): Promise<VerifyOutcome> {
  const d = store.domain(id)
  if (!d) return { ok: false, message: 'Domain not found.' }
  let method: 'dns' | 'meta' | undefined
  if (await checkDns(d)) method = 'dns'
  else if (await checkMeta(d)) method = 'meta'

  if (method) {
    store.upsertDomain({ ...d, verified: true, verifiedAt: new Date().toISOString(), verifiedBy: method })
    return { ok: true, method, message: `Verified via ${method === 'dns' ? 'DNS TXT record' : 'meta tag'}.` }
  }
  store.upsertDomain({ ...d, verified: false, verifiedAt: undefined, verifiedBy: undefined })
  return {
    ok: false,
    message:
      'Neither the DNS TXT record nor the meta tag was found. DNS changes can take a few minutes to appear; try again shortly.'
  }
}

/** Throws unless the domain is verified (re-verifying if the last check is stale). */
export async function assertVerified(id: string): Promise<Domain> {
  const d = store.domain(id)
  if (!d) throw new Error('Domain not found.')
  if (!d.verified) throw new Error(`Verify that you own ${d.host} before scanning it.`)
  const age = Date.now() - new Date(d.verifiedAt ?? 0).getTime()
  if (age > REVERIFY_AFTER_MS) {
    const r = await verifyDomain(id)
    if (!r.ok) throw new Error(`Ownership of ${d.host} could not be re-confirmed: ${r.message}`)
  }
  return store.domain(id)!
}
