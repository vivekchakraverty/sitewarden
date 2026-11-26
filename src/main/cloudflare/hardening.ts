// One-click zone hardening. Every change is snapshotted first so it can be reverted from the app.
// Rules are added one at a time with SiteWarden-specific refs, so the user's own rules are never replaced.
import type { ApplyResult, CspCheck, HardeningItem, ZoneHardening } from '../../shared/types'
import { checkCsp } from '../csp'
import { assertVerified } from '../domains'
import { store } from '../store'
import { cf, CfError } from './api'
import { agentConfig, token } from './deploy'

interface Zone {
  id: string
  name: string
  plan?: { name?: string }
}

interface Rule {
  id?: string
  ref?: string
  version?: string
  last_updated?: string
  [k: string]: unknown
}

interface Ctx {
  t: string
  zone: Zone
  host: string
}

interface ItemDef {
  id: string
  label: string
  description: string
  warning?: string
  recommendedByDefault: boolean
  recommendedText: string
  /** Current state as a JSON-serialisable snapshot. */
  read(c: Ctx): Promise<unknown>
  describe(snapshot: unknown): string
  isDone(snapshot: unknown): boolean
  apply(c: Ctx): Promise<unknown>
  restore(c: Ctx, snapshot: unknown): Promise<void>
  precondition?(): string | null
  /** Not listed in the hardening table; applied by its own flow but revertable like the rest. */
  hidden?: boolean
}

// ---------- helpers ----------

async function getSetting(c: Ctx, name: string): Promise<unknown> {
  return (await cf<{ value: unknown }>(c.t, 'GET', `/zones/${c.zone.id}/settings/${name}`)).value
}
async function setSetting(c: Ctx, name: string, value: unknown): Promise<void> {
  await cf(c.t, 'PATCH', `/zones/${c.zone.id}/settings/${name}`, { value })
}

async function entrypoint(c: Ctx, phase: string): Promise<{ id: string; rules: Rule[] } | null> {
  try {
    const r = await cf<{ id: string; rules?: Rule[] }>(c.t, 'GET', `/zones/${c.zone.id}/rulesets/phases/${phase}/entrypoint`)
    return { id: r.id, rules: r.rules ?? [] }
  } catch (e) {
    if (e instanceof CfError && e.status === 404) return null
    throw e
  }
}

const cleanRule = (r: Rule): Rule => {
  const { id: _id, version: _v, last_updated: _l, ...rest } = r
  return rest
}

async function findRule(c: Ctx, phase: string, ref: string): Promise<Rule | null> {
  const ep = await entrypoint(c, phase)
  return ep?.rules.find((r) => r.ref === ref) ?? null
}

async function upsertRule(c: Ctx, phase: string, rule: Rule): Promise<void> {
  const ep = await entrypoint(c, phase)
  if (!ep) {
    await cf(c.t, 'PUT', `/zones/${c.zone.id}/rulesets/phases/${phase}/entrypoint`, { rules: [rule] })
    return
  }
  const existing = ep.rules.find((r) => r.ref === rule.ref)
  if (existing?.id) await cf(c.t, 'PATCH', `/zones/${c.zone.id}/rulesets/${ep.id}/rules/${existing.id}`, rule)
  else await cf(c.t, 'POST', `/zones/${c.zone.id}/rulesets/${ep.id}/rules`, rule)
}

async function removeRule(c: Ctx, phase: string, ref: string): Promise<void> {
  const ep = await entrypoint(c, phase)
  const existing = ep?.rules.find((r) => r.ref === ref)
  if (ep && existing?.id) await cf(c.t, 'DELETE', `/zones/${c.zone.id}/rulesets/${ep.id}/rules/${existing.id}`)
}

function hostExpr(host: string): string {
  const hosts = host.startsWith('www.') ? [host] : [host, `www.${host}`]
  return `(http.host in {${hosts.map((h) => `"${h}"`).join(' ')}})`
}

function settingItem(
  id: string,
  setting: string,
  label: string,
  description: string,
  target: unknown,
  opts: { warning?: string; byDefault?: boolean; done?: (v: unknown) => boolean; text?: string } = {}
): ItemDef {
  return {
    id,
    label,
    description,
    warning: opts.warning,
    recommendedByDefault: opts.byDefault ?? true,
    recommendedText: opts.text ?? String(target),
    read: (c) => getSetting(c, setting),
    describe: (v) => (typeof v === 'object' ? JSON.stringify(v) : String(v)),
    isDone: (v) => (opts.done ? opts.done(v) : v === target),
    apply: async (c) => {
      await setSetting(c, setting, target)
      return target
    },
    restore: (c, v) => setSetting(c, setting, v)
  }
}

function ruleItem(
  id: string,
  phase: string,
  ref: string,
  label: string,
  description: string,
  build: (c: Ctx) => Rule,
  opts: { warning?: string; byDefault?: boolean; precondition?: () => string | null }
): ItemDef {
  return {
    id,
    label,
    description,
    warning: opts.warning,
    recommendedByDefault: opts.byDefault ?? true,
    recommendedText: 'rule added',
    precondition: opts.precondition,
    read: (c) => findRule(c, phase, ref),
    describe: (r) => (r ? 'rule present' : 'not set'),
    isDone: (r) => Boolean(r),
    apply: async (c) => {
      const rule = { ref, ...build(c) }
      await upsertRule(c, phase, rule)
      return rule
    },
    restore: async (c, prev) => {
      if (prev) await upsertRule(c, phase, cleanRule(prev as Rule))
      else await removeRule(c, phase, ref)
    }
  }
}

const HEADERS_PHASE = 'http_response_headers_transform'
const CSP_FIX_REF = 'sitewarden_csp_allow_agent'

const ITEMS: ItemDef[] = [
  settingItem('always_https', 'always_use_https', 'Always use HTTPS', 'Redirects every http:// request to https://.', 'on'),
  settingItem('min_tls', 'min_tls_version', 'Minimum TLS 1.2', 'Refuses outdated TLS 1.0/1.1 connections.', '1.2', {
    done: (v) => v === '1.2' || v === '1.3'
  }),
  settingItem('https_rewrites', 'automatic_https_rewrites', 'Automatic HTTPS rewrites', 'Rewrites http:// links in your pages to https:// to fix mixed content.', 'on'),
  {
    id: 'bot_fight',
    label: 'Bot Fight Mode',
    description: 'Challenges traffic that matches known bad bots (free plan feature).',
    warning: 'It can challenge legitimate automated clients such as uptime monitors, payment webhooks or mobile apps, and it cannot be bypassed with rules.',
    recommendedByDefault: true,
    recommendedText: 'on',
    read: async (c) => (await cf<{ fight_mode?: boolean }>(c.t, 'GET', `/zones/${c.zone.id}/bot_management`)).fight_mode ?? false,
    describe: (v) => (v ? 'on' : 'off'),
    isDone: (v) => v === true,
    apply: async (c) => {
      await cf(c.t, 'PUT', `/zones/${c.zone.id}/bot_management`, { fight_mode: true })
      return true
    },
    restore: async (c, v) => {
      await cf(c.t, 'PUT', `/zones/${c.zone.id}/bot_management`, { fight_mode: Boolean(v) })
    }
  },
  ruleItem(
    'security_headers',
    HEADERS_PHASE,
    'sitewarden_security_headers',
    'Security headers',
    'Adds X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy to every response.',
    (c) => ({
      description: 'SiteWarden: security headers',
      expression: hostExpr(c.host),
      action: 'rewrite',
      enabled: true,
      action_parameters: {
        headers: {
          'X-Content-Type-Options': { operation: 'set', value: 'nosniff' },
          'X-Frame-Options': { operation: 'set', value: 'SAMEORIGIN' },
          'Referrer-Policy': { operation: 'set', value: 'strict-origin-when-cross-origin' },
          'Permissions-Policy': { operation: 'set', value: 'camera=(), microphone=(), geolocation=(), payment=()' }
        }
      }
    }),
    { warning: 'X-Frame-Options SAMEORIGIN stops other sites from embedding your pages in a frame. Skip this if you rely on that.' }
  ),
  ruleItem(
    'csp_report_only',
    HEADERS_PHASE,
    'sitewarden_csp_report_only',
    'CSP in report-only mode',
    'Sends a Content-Security-Policy-Report-Only header that reports external scripts and plugins to your agent. Nothing is blocked.',
    (c) => {
      const agent = agentConfig()!
      return {
        description: 'SiteWarden: CSP report-only',
        expression: hostExpr(c.host),
        action: 'rewrite',
        enabled: true,
        action_parameters: {
          headers: {
            'Content-Security-Policy-Report-Only': {
              operation: 'set',
              value: `script-src 'self' 'unsafe-inline' 'unsafe-eval' 'report-sample'; object-src 'none'; base-uri 'self'; report-uri ${agent.workerUrl}/r/csp?site=${c.host}`
            }
          }
        }
      }
    },
    {
      byDefault: false,
      warning: 'Each report is one request to your Worker (free plan: 100,000 a day). Busy sites with many third-party scripts can use that up.',
      precondition: () => (agentConfig() ? null : 'Deploy the agent on the Cloudflare page first.')
    }
  ),
  ruleItem(
    'login_rate_limit',
    'http_ratelimit',
    'sitewarden_login_rate_limit',
    'Rate-limit login pages',
    'Blocks an IP for 10 seconds after 5 login POSTs in 10 seconds on common login paths (WordPress, /login, /admin).',
    () => ({
      description: 'SiteWarden: login brute-force limit',
      expression:
        '(http.request.method eq "POST" and http.request.uri.path in {"/wp-login.php" "/xmlrpc.php" "/login" "/admin/login" "/user/login" "/account/login"})',
      action: 'block',
      enabled: true,
      ratelimit: { characteristics: ['cf.colo.id', 'ip.src'], period: 10, requests_per_period: 5, mitigation_timeout: 10 }
    }),
    { byDefault: false, warning: 'The free plan allows only one rate-limiting rule per zone; this fails if you already have one.' }
  ),
  settingItem(
    'hsts',
    'security_header',
    'HSTS (6 months)',
    'Tells browsers to only ever use HTTPS for this domain.',
    { strict_transport_security: { enabled: true, max_age: 15552000, include_subdomains: false, preload: false, nosniff: true } },
    {
      byDefault: false,
      text: 'enabled, 6 months',
      warning: 'Hard to undo: browsers that saw the header keep refusing HTTP for 6 months even if you turn it off. Only enable once HTTPS works everywhere on this host.',
      done: (v) => Boolean((v as { strict_transport_security?: { enabled?: boolean } })?.strict_transport_security?.enabled)
    }
  ),
  {
    id: 'csp_allow_agent',
    label: 'CSP: allow the SiteWarden agent',
    description: "Overrides your site's Content-Security-Policy header with a copy that also allows the agent.",
    recommendedByDefault: false,
    recommendedText: 'patched',
    hidden: true,
    read: (c) => findRule(c, HEADERS_PHASE, CSP_FIX_REF),
    describe: (r) => (r ? 'rule present' : 'not set'),
    isDone: (r) => Boolean(r),
    apply: () => Promise.reject(new Error('Use the CSP fix button.')),
    restore: async (c, prev) => {
      if (prev) await upsertRule(c, HEADERS_PHASE, cleanRule(prev as Rule))
      else await removeRule(c, HEADERS_PHASE, CSP_FIX_REF)
    }
  },
  settingItem('ssl_strict', 'ssl', 'SSL mode: Full (strict)', 'Encrypts and verifies the connection between Cloudflare and your server.', 'strict', {
    byDefault: false,
    warning: 'Your site goes down (error 526) if your server does not have a valid certificate. Check your origin certificate first.'
  })
]

// ---------- zone lookup ----------

async function findZone(t: string, host: string): Promise<Zone | null> {
  const labels = host.split('.')
  for (let i = 0; i <= labels.length - 2; i++) {
    const name = labels.slice(i).join('.')
    const zones = await cf<Zone[]>(t, 'GET', `/zones?name=${encodeURIComponent(name)}`)
    if (zones.length) return zones[0]
  }
  return null
}

async function context(domainId: string): Promise<Ctx> {
  const d = await assertVerified(domainId)
  const t = token()
  const zone = await findZone(t, d.host)
  if (!zone) throw new Error(`${d.host} is not a zone in this Cloudflare account. Add the site to Cloudflare (and switch its nameservers) first.`)
  return { t, zone, host: d.host }
}

// ---------- public ----------

export async function hardening(domainId: string): Promise<ZoneHardening> {
  let c: Ctx
  try {
    c = await context(domainId)
  } catch (e) {
    return { items: [], error: (e as Error).message }
  }
  const items: HardeningItem[] = await Promise.all(
    ITEMS.filter((i) => !i.hidden).map(async (def): Promise<HardeningItem> => {
      const base = {
        id: def.id,
        label: def.label,
        description: def.description,
        warning: def.warning,
        recommended: def.recommendedText,
        recommendedByDefault: def.recommendedByDefault
      }
      const pre = def.precondition?.()
      try {
        const snap = await def.read(c)
        return { ...base, current: def.describe(snap), done: def.isDone(snap), available: !pre, note: pre ?? undefined }
      } catch (e) {
        return { ...base, current: 'unknown', done: false, available: false, note: (e as Error).message }
      }
    })
  )
  return { zoneId: c.zone.id, zoneName: c.zone.name, plan: c.zone.plan?.name, items }
}

export async function applyItems(domainId: string, ids: string[]): Promise<ApplyResult[]> {
  const c = await context(domainId)
  const results: ApplyResult[] = []
  for (const id of ids) {
    const def = ITEMS.find((i) => i.id === id && !i.hidden)
    if (!def) {
      results.push({ id, ok: false, message: 'Unknown item' })
      continue
    }
    const pre = def.precondition?.()
    if (pre) {
      results.push({ id, ok: false, message: pre })
      continue
    }
    try {
      const previous = await def.read(c)
      if (def.isDone(previous) && !id.startsWith('csp') && id !== 'security_headers') {
        results.push({ id, ok: true, message: 'Already set' })
        continue
      }
      const applied = await def.apply(c)
      store.addChange({
        domainId,
        zoneId: c.zone.id,
        item: id,
        label: def.label,
        previous: JSON.stringify(previous ?? null),
        applied: JSON.stringify(applied ?? null),
        appliedAt: new Date().toISOString()
      })
      results.push({ id, ok: true, message: 'Applied' })
    } catch (e) {
      results.push({ id, ok: false, message: (e as Error).message })
    }
  }
  return results
}

export async function revert(changeId: number): Promise<ApplyResult> {
  const ch = store.change(changeId)
  if (!ch) return { id: String(changeId), ok: false, message: 'Change not found' }
  if (ch.revertedAt) return { id: ch.item, ok: true, message: 'Already reverted' }
  const def = ITEMS.find((i) => i.id === ch.item)
  if (!def) return { id: ch.item, ok: false, message: 'Unknown item' }
  try {
    const c = await context(ch.domainId)
    if (c.zone.id !== ch.zoneId) throw new Error('The zone has changed since this was applied.')
    await def.restore(c, JSON.parse(ch.previous))
    store.markReverted(changeId)
    return { id: ch.item, ok: true, message: `Restored ${def.label}` }
  } catch (e) {
    return { id: ch.item, ok: false, message: (e as Error).message }
  }
}

/** Re-checks the live policy and, if it is safe to, overrides the CSP header with the patched copy. */
export async function applyCspFix(domainId: string): Promise<{ result: ApplyResult; check: CspCheck }> {
  const c = await context(domainId)
  const agent = agentConfig()
  if (!agent) throw new Error('Deploy the agent first.')
  const before = await checkCsp(c.host, agent.workerUrl, true)
  if (!before.canAutoFix || !before.headerPatched) {
    return { result: { id: 'csp_allow_agent', ok: false, message: before.autoFixNote ?? 'Nothing to fix.' }, check: before }
  }
  const def = ITEMS.find((i) => i.id === 'csp_allow_agent')!
  const previous = await def.read(c)
  const rule: Rule = {
    ref: CSP_FIX_REF,
    description: 'SiteWarden: CSP with the monitoring agent allowed',
    expression: hostExpr(c.host),
    action: 'rewrite',
    enabled: true,
    action_parameters: { headers: { 'Content-Security-Policy': { operation: 'set', value: before.headerPatched } } }
  }
  await upsertRule(c, HEADERS_PHASE, rule)
  store.addChange({
    domainId,
    zoneId: c.zone.id,
    item: def.id,
    label: def.label,
    previous: JSON.stringify(previous ?? null),
    applied: JSON.stringify(rule),
    appliedAt: new Date().toISOString()
  })
  // Cloudflare rules apply within seconds; re-check so the UI shows the new state.
  await new Promise((r) => setTimeout(r, 3000))
  const after = await checkCsp(c.host, agent.workerUrl, true)
  return { result: { id: def.id, ok: true, message: 'Cloudflare now sends the patched policy.' }, check: after }
}

export async function cspCheck(domainId: string): Promise<CspCheck> {
  const d = await assertVerified(domainId)
  const agent = agentConfig()
  if (!agent) throw new Error('Deploy the agent first.')
  let connected = true
  try {
    token()
  } catch {
    connected = false
  }
  return checkCsp(d.host, agent.workerUrl, connected)
}
