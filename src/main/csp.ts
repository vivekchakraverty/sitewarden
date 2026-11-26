// Checks whether a site's Content-Security-Policy lets guard.js load and report, and builds a patched policy.
// guard.js needs: a <script> from the agent origin (script-src-elem > script-src > default-src)
// and a sendBeacon to it (connect-src > default-src).
import type { CspCheck } from '../shared/types'
import { get } from './http'

type Policy = Map<string, string[]> // directive -> sources, in original order

export function parsePolicy(text: string): Policy {
  const p: Policy = new Map()
  for (const part of text.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean)
    if (!tokens.length) continue
    const name = tokens[0].toLowerCase()
    if (!p.has(name)) p.set(name, tokens.slice(1)) // first occurrence wins, as in browsers
  }
  return p
}

export function serializePolicy(p: Policy): string {
  return [...p].map(([k, v]) => (v.length ? `${k} ${v.join(' ')}` : k)).join('; ')
}

/** Does this source list allow loading `url`? (Ignores 'self': the agent is never same-origin.) */
export function sourcesAllow(sources: string[], url: URL): boolean {
  for (const raw of sources) {
    const s = raw.toLowerCase()
    if (s === '*' || s === 'https:') return true
    if (s.startsWith("'")) continue // keywords, nonces, hashes
    const m = /^(?:(https?):\/\/)?(\*\.)?([a-z0-9.-]+)(?::(\d+|\*))?(\/.*)?$/.exec(s)
    if (!m) continue
    const [, , wildcard, host, port, path] = m // http:// sources also match https in CSP3
    if (port && port !== '*' && port !== '443') continue
    const hostOk = wildcard ? url.hostname.endsWith(`.${host}`) : url.hostname === host
    if (!hostOk) continue
    // CSP path rules: a path ending in "/" is a prefix, anything else must match exactly.
    if (path && path !== '/' && !(path.endsWith('/') ? url.pathname.startsWith(path) : url.pathname === path)) continue
    return true
  }
  return false
}

interface DirectiveFix {
  effective: string | null // which directive governs, null = nothing restricts
  allowed: boolean
}

function effective(p: Policy, chain: string[], url: URL): DirectiveFix {
  for (const d of chain) {
    const s = p.get(d)
    if (s) return { effective: d, allowed: sourcesAllow(s, url) }
  }
  return { effective: null, allowed: true }
}

const SCRIPT_CHAIN = ['script-src-elem', 'script-src', 'default-src']
const CONNECT_CHAIN = ['connect-src', 'default-src']

function addSource(p: Policy, directive: string, origin: string, fallbackFrom?: string): void {
  let list = p.get(directive)
  if (!list) list = fallbackFrom ? [...(p.get(fallbackFrom) ?? [])] : []
  list = list.filter((s) => s.toLowerCase() !== "'none'")
  if (!list.includes(origin)) list.push(origin)
  p.set(directive, list)
}

export interface PolicyAnalysis {
  problems: string[]
  strictDynamic: boolean
  hasNonce: boolean
  patched: string
}

export function analysePolicy(text: string, workerOrigin: string): PolicyAnalysis {
  const p = parsePolicy(text)
  const problems: string[] = []
  const script = effective(p, SCRIPT_CHAIN, new URL(`${workerOrigin}/guard.js`))
  const connect = effective(p, CONNECT_CHAIN, new URL(`${workerOrigin}/r/guard`))
  const scriptSources = (script.effective && p.get(script.effective)) || []
  const strictDynamic = scriptSources.some((s) => s.toLowerCase() === "'strict-dynamic'")
  const hasNonce = /'nonce-/i.test(text)

  if (strictDynamic) problems.push(`${script.effective} uses 'strict-dynamic', so browsers ignore host allowlists for scripts`)
  else if (!script.allowed) problems.push(`${script.effective} blocks guard.js from loading`)
  if (!connect.allowed) problems.push(`${connect.effective} blocks guard.js from sending its report`)

  if (!script.allowed && !strictDynamic) {
    // Patch the directive that actually governs <script> elements. If only default-src exists, add a
    // script-src copied from it instead of widening default-src for everything else.
    addSource(p, script.effective === 'default-src' ? 'script-src' : script.effective!, workerOrigin, script.effective === 'default-src' ? 'default-src' : undefined)
  }
  if (!connect.allowed) {
    addSource(p, connect.effective === 'default-src' ? 'connect-src' : connect.effective!, workerOrigin, connect.effective === 'default-src' ? 'default-src' : undefined)
  }
  return { problems, strictDynamic, hasNonce, patched: serializePolicy(p) }
}

/** A header may hold several policies joined by commas; each is enforced separately. */
function analyseAll(value: string, workerOrigin: string): PolicyAnalysis {
  const parts = value.split(',').map((s) => s.trim()).filter(Boolean)
  const results = parts.map((p) => analysePolicy(p, workerOrigin))
  return {
    problems: [...new Set(results.flatMap((r) => r.problems))],
    strictDynamic: results.some((r) => r.strictDynamic),
    hasNonce: results.some((r) => r.hasNonce),
    patched: results.map((r) => r.patched).join(', ')
  }
}

function metaPolicy(html: string): string | undefined {
  for (const tag of html.match(/<meta\b[^>]*>/gi) ?? []) {
    if (!/http-equiv\s*=\s*["']?content-security-policy["'\s>]/i.test(tag)) continue
    const m = /content\s*=\s*("([^"]*)"|'([^']*)')/i.exec(tag)
    if (m) return (m[2] ?? m[3]).replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&')
  }
  return undefined
}

export async function checkCsp(host: string, workerOrigin: string, cloudflareConnected: boolean): Promise<CspCheck> {
  const base: CspCheck = { status: 'error', workerOrigin, inHeader: false, inMeta: false, reportOnly: false, problems: [], canAutoFix: false }
  let page
  try {
    page = await get(`https://${host}/`, { timeoutMs: 15000 })
  } catch (e) {
    return { ...base, error: `Could not load https://${host}/: ${(e as Error).message}` }
  }
  const header = page.headers.get('content-security-policy') ?? undefined
  const meta = metaPolicy(page.body)
  const reportOnly = Boolean(page.headers.get('content-security-policy-report-only'))
  const r: CspCheck = { ...base, status: 'none', inHeader: Boolean(header), inMeta: Boolean(meta), reportOnly, header, meta }
  if (!header && !meta) return r

  const h = header ? analyseAll(header, workerOrigin) : null
  const m = meta ? analysePolicy(meta, workerOrigin) : null
  r.problems = [...new Set([...(h?.problems ?? []), ...(m?.problems ?? [])])]
  if (h?.problems.length) r.headerPatched = h.patched
  if (m?.problems.length) r.metaPatched = m.patched

  if (!r.problems.length) return { ...r, status: 'allowed' }
  r.status = h?.strictDynamic || m?.strictDynamic ? 'nonce' : 'blocked'

  // One-click fix: Cloudflare overrides the response header with the patched copy. Only safe when the
  // policy is static (no per-request nonce) and nothing in a meta tag would still block.
  if (!cloudflareConnected) r.autoFixNote = 'Connect Cloudflare to fix this in one click.'
  else if (!h?.problems.length) r.autoFixNote = 'The blocking policy is in a <meta> tag in your HTML, which Cloudflare cannot change. Edit the tag instead.'
  else if (m?.problems.length) r.autoFixNote = 'Your page also has a blocking <meta> CSP tag. Edit that tag as well; Cloudflare cannot change it.'
  else if (h.hasNonce) r.autoFixNote = 'Your CSP uses a nonce that changes on every request, so a fixed copy would break your own scripts. Update it on your server instead.'
  else if (r.status === 'nonce') r.autoFixNote = "'strict-dynamic' needs a nonce on the guard tag, which has to be added in your templates."
  else r.canAutoFix = true
  return r
}
