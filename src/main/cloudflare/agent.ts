// Reads monitoring data back from the user's deployed agent Worker.
import type { AgentSummary } from '../../shared/types'
import { store } from '../store'
import { agentConfig } from './deploy'

function config(domainId: string): { base: string; auth: string; host: string } {
  const d = store.domain(domainId)
  if (!d) throw new Error('Domain not found.')
  const a = agentConfig()
  if (!a) throw new Error('The agent is not deployed yet.')
  if (!a.sites.includes(d.host)) throw new Error(`${d.host} was added after the last deploy. Redeploy the agent on the Cloudflare page to include it.`)
  return { base: a.workerUrl, auth: `Bearer ${a.agentToken}`, host: d.host }
}

async function call<T>(domainId: string, method: string, path: string, body?: unknown): Promise<T> {
  const c = config(domainId)
  const res = await fetch(`${c.base}${path}?site=${encodeURIComponent(c.host)}`, {
    method,
    headers: { Authorization: c.auth, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15000)
  })
  if (res.status === 401) throw new Error('The agent rejected our token. Redeploy the agent to resync it.')
  if (!res.ok) throw new Error(`Agent returned HTTP ${res.status}`)
  return (await res.json()) as T
}

export const agentSummary = (domainId: string): Promise<AgentSummary> => call(domainId, 'GET', '/api/summary')

export async function agentApprove(domainId: string, origin: string, approved: boolean): Promise<void> {
  await call(domainId, 'POST', '/api/approve', { origin, approved })
}

export async function agentAck(domainId: string): Promise<void> {
  await call(domainId, 'POST', '/api/ack', {})
}

export function guardSnippet(domainId: string): string | null {
  const d = store.domain(domainId)
  const a = agentConfig()
  if (!d || !a || !a.sites.includes(d.host)) return null
  return `<script src="${a.workerUrl}/guard.js?site=${encodeURIComponent(d.host)}" async></script>`
}
