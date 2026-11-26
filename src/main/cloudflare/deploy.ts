// Connects to the user's Cloudflare account and deploys the SiteWarden agent Worker into it.
import { randomBytes } from 'crypto'
import type { CfAccount, CfStatus, DeployOptions, DeployResult } from '../../shared/types'
import { clearKey, getKey, setSecret } from '../secrets'
import { store } from '../store'
import { cf, cfAll, CfError } from './api'
import agentSource from '../../worker/agent.js?raw'
import guardSource from '../../worker/guard.js?raw'

export const SCRIPT_NAME = 'sitewarden-agent'
const DB_NAME = 'sitewarden-agent'
const CRON = '*/30 * * * *'
const GUARD_SAMPLE = '0.1'

interface Saved {
  accountId?: string
  workerUrl?: string
  dbId?: string
  deployedAt?: string
  sites?: string[]
  keysCopied?: boolean
}

const saved = (): Saved => store.get<Saved>('cf') ?? {}
const save = (s: Saved): void => store.set('cf', s)

export function token(): string {
  const t = getKey('cloudflareToken')
  if (!t) throw new Error('Connect your Cloudflare account first.')
  return t
}

async function listAccounts(t: string): Promise<CfAccount[]> {
  const accounts = await cfAll<{ id: string; name: string }>(t, '/accounts')
  return accounts.map((a) => ({ id: a.id, name: a.name }))
}

export async function status(): Promise<CfStatus> {
  const s = saved()
  const t = getKey('cloudflareToken')
  let accounts: CfAccount[] = []
  if (t) {
    try {
      accounts = await listAccounts(t)
    } catch {
      // offline or token revoked; still show what we know
    }
  }
  return {
    connected: Boolean(t),
    accounts,
    accountId: s.accountId,
    workerUrl: s.workerUrl,
    deployedAt: s.deployedAt,
    deployedSites: s.sites ?? [],
    alertWebhookSet: Boolean(getKey('alertWebhook')),
    keysCopied: Boolean(s.keysCopied)
  }
}

export async function connect(t: string): Promise<CfStatus> {
  const trimmed = t.trim()
  if (!/^[A-Za-z0-9_-]{30,}$/.test(trimmed)) throw new Error('That does not look like a Cloudflare API token.')
  let accounts: CfAccount[]
  try {
    accounts = await listAccounts(trimmed)
  } catch (e) {
    throw new Error(`Cloudflare rejected the token: ${(e as Error).message}`)
  }
  if (!accounts.length) throw new Error('The token works but cannot see any account. Give it access to your account (Account Resources > Include > your account).')
  setSecret('cloudflareToken', trimmed)
  const s = saved()
  if (!s.accountId || !accounts.some((a) => a.id === s.accountId)) save({ ...s, accountId: accounts[0].id })
  return status()
}

export function disconnect(): void {
  clearKey('cloudflareToken')
}

async function ensureDatabase(t: string, accountId: string): Promise<string> {
  const list = await cf<{ uuid: string; name: string }[]>(t, 'GET', `/accounts/${accountId}/d1/database?name=${DB_NAME}`)
  const found = list.find((d) => d.name === DB_NAME)
  if (found) return found.uuid
  const created = await cf<{ uuid: string }>(t, 'POST', `/accounts/${accountId}/d1/database`, { name: DB_NAME })
  return created.uuid
}

async function workersSubdomain(t: string, accountId: string): Promise<string> {
  try {
    const r = await cf<{ subdomain: string }>(t, 'GET', `/accounts/${accountId}/workers/subdomain`)
    if (r.subdomain) return r.subdomain
  } catch (e) {
    if (!(e instanceof CfError) || e.status !== 404) throw e
  }
  throw new Error(
    'Your account has no workers.dev subdomain yet. Open Cloudflare dashboard > Workers & Pages once (it asks you to pick a subdomain), then deploy again.'
  )
}

export function buildWorkerSource(): string {
  return agentSource.replace('__GUARD_SOURCE__', JSON.stringify(guardSource))
}

export async function deploy(opts: DeployOptions): Promise<DeployResult> {
  const t = token()
  const steps: string[] = []
  const sites = store
    .domains()
    .filter((d) => d.verified)
    .map((d) => d.host)
  if (!sites.length) throw new Error('Verify at least one domain before deploying the agent.')

  if (opts.alertWebhook !== undefined) {
    const w = opts.alertWebhook.trim()
    if (w && !/^https:\/\//.test(w)) throw new Error('The alert webhook must be an https:// URL.')
    if (w) setSecret('alertWebhook', w)
    else clearKey('alertWebhook')
  }
  let agentToken = getKey('agentToken')
  if (!agentToken) {
    agentToken = randomBytes(32).toString('base64url')
    setSecret('agentToken', agentToken)
  }

  const dbId = await ensureDatabase(t, opts.accountId)
  steps.push(`D1 database "${DB_NAME}" ready`)

  const bindings: Record<string, string>[] = [
    { type: 'd1', name: 'DB', id: dbId },
    { type: 'secret_text', name: 'AGENT_TOKEN', text: agentToken },
    { type: 'plain_text', name: 'SITES', text: JSON.stringify(sites) },
    { type: 'plain_text', name: 'GUARD_SAMPLE', text: GUARD_SAMPLE }
  ]
  const webhook = getKey('alertWebhook')
  if (webhook) bindings.push({ type: 'secret_text', name: 'ALERT_WEBHOOK', text: webhook })
  const vmToken = getKey('vmToken')
  if (vmToken) bindings.push({ type: 'secret_text', name: 'VM_TOKEN', text: vmToken })
  let keysCopied = false
  if (opts.copyKeys) {
    const sb = getKey('safeBrowsing')
    const uh = getKey('urlhaus')
    if (sb) bindings.push({ type: 'secret_text', name: 'SB_KEY', text: sb })
    if (uh) bindings.push({ type: 'secret_text', name: 'URLHAUS_KEY', text: uh })
    keysCopied = Boolean(sb || uh)
  }

  const form = new FormData()
  form.append(
    'metadata',
    new Blob([JSON.stringify({ main_module: 'agent.js', compatibility_date: '2026-11-01', bindings })], { type: 'application/json' })
  )
  form.append('agent.js', new Blob([buildWorkerSource()], { type: 'application/javascript+module' }), 'agent.js')
  await cf(t, 'PUT', `/accounts/${opts.accountId}/workers/scripts/${SCRIPT_NAME}`, undefined, { form, timeoutMs: 60000 })
  steps.push(`Worker "${SCRIPT_NAME}" uploaded for ${sites.length} site(s)`)

  await cf(t, 'PUT', `/accounts/${opts.accountId}/workers/scripts/${SCRIPT_NAME}/schedules`, [{ cron: CRON }])
  steps.push('Checks scheduled every 30 minutes')

  const sub = await workersSubdomain(t, opts.accountId)
  await cf(t, 'POST', `/accounts/${opts.accountId}/workers/scripts/${SCRIPT_NAME}/subdomain`, { enabled: true, previews_enabled: false })
  const workerUrl = `https://${SCRIPT_NAME}.${sub}.workers.dev`
  steps.push(`Published at ${workerUrl}`)

  save({ accountId: opts.accountId, workerUrl, dbId, deployedAt: new Date().toISOString(), sites, keysCopied })

  // workers.dev routes can take a few seconds to go live.
  let live = false
  for (let i = 0; i < 6 && !live; i++) {
    try {
      const r = await fetch(`${workerUrl}/api/ping`, { headers: { Authorization: `Bearer ${agentToken}` }, signal: AbortSignal.timeout(8000) })
      live = r.ok
    } catch {
      // not yet
    }
    if (!live) await new Promise((r) => setTimeout(r, 3000))
  }
  steps.push(live ? 'Agent answered the health check' : 'Agent is deployed but not answering yet; workers.dev can take a minute. Refresh the Protection tab shortly.')
  return { workerUrl, sites, steps }
}

/** Redeploys with the options of the last deploy (used when domains or the VM token change). */
export async function redeploy(): Promise<DeployResult> {
  const s = saved()
  if (!s.accountId || !s.workerUrl) throw new Error('Deploy the agent on the Cloudflare page first.')
  return deploy({ accountId: s.accountId, copyKeys: Boolean(s.keysCopied) })
}

export async function removeAgent(): Promise<void> {
  const s = saved()
  if (!s.accountId) return
  try {
    await cf(token(), 'DELETE', `/accounts/${s.accountId}/workers/scripts/${SCRIPT_NAME}?force=true`)
  } catch (e) {
    if (!(e instanceof CfError) || e.status !== 404) throw e
  }
  // The D1 database is left in place so history isn't lost; the user can delete it in the dashboard.
  save({ accountId: s.accountId })
}

export function agentConfig(): { workerUrl: string; agentToken: string; sites: string[] } | null {
  const s = saved()
  const agentToken = getKey('agentToken')
  if (!s.workerUrl || !agentToken) return null
  return { workerUrl: s.workerUrl, agentToken, sites: s.sites ?? [] }
}
