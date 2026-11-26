// Oracle Cloud (or any Linux + Docker) scan agent: token, cloud-init, schedule, and importing its results.
// The VM never accepts connections; it polls the user's Cloudflare agent Worker, which acts as the mailbox.
import { randomBytes } from 'crypto'
import type { CheckRun, ScanResult, VmSettings, VmStatus } from '../../shared/types'
import { agentConfig, redeploy } from '../cloudflare/deploy'
import { score, SEVERITY_ORDER } from '../scanners'
import { parseNucleiOutput } from '../scanners/nuclei'
import { parseZapReport } from '../scanners/zap'
import { clearKey, getKey, setSecret } from '../secrets'
import { store } from '../store'
import agentPy from '../../oracle/agent.py?raw'

const LAST_IMPORTED = 'vm.lastImported'

function agent(): { workerUrl: string; agentToken: string; sites: string[] } {
  const a = agentConfig()
  if (!a) throw new Error('Deploy the Cloudflare agent first: the VM uses it as its mailbox.')
  return a
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const a = agent()
  const res = await fetch(`${a.workerUrl}${path}`, {
    method,
    headers: { Authorization: `Bearer ${a.agentToken}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000)
  })
  if (res.status === 404 && path.startsWith('/api/vm/')) throw new Error('Your Worker is an older version without VM support. Redeploy it on the Cloudflare page.')
  if (!res.ok) throw new Error(`Agent returned HTTP ${res.status}`)
  return (await res.json()) as T
}

type RemoteStatus = Omit<VmStatus, 'available' | 'reason' | 'tokenCreated' | 'needsRedeploy' | 'sites'> & { tokenConfigured: boolean }

export async function status(): Promise<VmStatus> {
  const a = agentConfig()
  const tokenCreated = Boolean(getKey('vmToken'))
  const empty = { tokenCreated, needsRedeploy: false, jobs: [], latest: [], sites: a?.sites ?? [] }
  if (!a) return { ...empty, available: false, reason: 'Deploy the Cloudflare monitoring agent first. The VM sends its results through it, so it never needs an open port.' }
  try {
    const r = await call<RemoteStatus>('GET', '/api/vm/status')
    return {
      available: true,
      tokenCreated,
      needsRedeploy: tokenCreated && !r.tokenConfigured,
      heartbeat: r.heartbeat ?? undefined,
      settings: r.settings,
      jobs: r.jobs,
      latest: r.latest,
      sites: a.sites
    }
  } catch (e) {
    return { ...empty, available: true, needsRedeploy: /older version/.test((e as Error).message), reason: (e as Error).message }
  }
}

/** Creates the VM token (once) and pushes it to the Worker. */
export async function setup(): Promise<VmStatus> {
  agent()
  if (!getKey('vmToken')) setSecret('vmToken', randomBytes(32).toString('base64url'))
  const s = await status()
  if (s.needsRedeploy || s.reason) await redeploy()
  return status()
}

export async function rotateToken(): Promise<{ status: VmStatus; command: string }> {
  agent()
  const token = randomBytes(32).toString('base64url')
  const previous = getKey('vmToken')
  setSecret('vmToken', token)
  try {
    await redeploy()
  } catch (e) {
    if (previous) setSecret('vmToken', previous)
    else clearKey('vmToken')
    throw e
  }
  return { status: await status(), command: `sudo sitewarden-agent set-token ${token}` }
}

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64')
const indent = (s: string, n: number): string =>
  s
    .split('\n')
    .map((l) => (l ? ' '.repeat(n) + l : l))
    .join('\n')

export function buildCloudInit(workerUrl: string, token: string, generatedAt = new Date()): string {
  const conf = JSON.stringify({ worker: workerUrl, token }) + '\n'
  const service = `[Unit]
Description=SiteWarden scan agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/sitewarden/agent.py
TimeoutStartSec=4h
Nice=10
`
  const timer = `[Unit]
Description=Run the SiteWarden scan agent every 10 minutes

[Timer]
OnBootSec=3min
OnUnitInactiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
`
  const wrapper = `#!/bin/sh
exec /usr/bin/python3 /opt/sitewarden/agent.py "$@"
`
  return `#cloud-config
# SiteWarden scan agent, generated ${generatedAt.toISOString()}
# This file contains a secret token. Treat it like a password and don't share it.
# Tested for Ubuntu 22.04/24.04 images. The VM only makes outbound HTTPS requests; no ports need to be opened.
package_update: true
packages:
  - docker.io
  - python3
write_files:
  - path: /etc/sitewarden/agent.json
    permissions: '0600'
    encoding: b64
    content: ${b64(conf)}
  - path: /opt/sitewarden/agent.py
    permissions: '0755'
    encoding: b64
    content: ${b64(agentPy)}
  - path: /usr/local/bin/sitewarden-agent
    permissions: '0755'
    content: |
${indent(wrapper, 6)}
  - path: /etc/systemd/system/sitewarden-agent.service
    permissions: '0644'
    content: |
${indent(service, 6)}
  - path: /etc/systemd/system/sitewarden-agent.timer
    permissions: '0644'
    content: |
${indent(timer, 6)}
runcmd:
  - [systemctl, enable, --now, docker]
  - [docker, pull, projectdiscovery/nuclei:latest]
  - [docker, pull, zaproxy/zap-stable]
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, sitewarden-agent.timer]
`
}

export function cloudInit(): string {
  const a = agent()
  const token = getKey('vmToken')
  if (!token) throw new Error('Set up the VM agent first.')
  return buildCloudInit(a.workerUrl, token)
}

export async function scanNow(domainId: string): Promise<{ alreadyQueued: boolean }> {
  const d = store.domain(domainId)
  if (!d || !d.verified) throw new Error('Verify the domain first.')
  if (!agent().sites.includes(d.host)) throw new Error(`${d.host} was added after the last deploy. Redeploy the agent on the Cloudflare page first.`)
  return call('POST', `/api/vm/scan?site=${encodeURIComponent(d.host)}`, {})
}

export async function saveSettings(s: VmSettings): Promise<VmStatus> {
  await call('POST', '/api/vm/settings', s)
  return status()
}

interface RemoteResult {
  id: number
  site: string
  startedAt: string
  finishedAt: string
  nuclei: string
  zap: string
  errors: string[]
  agentVersion?: string
}

/** Turns one raw VM result into a scan in the history, using the same parsers as local deep scans. */
export function toScanResult(r: RemoteResult, domainId: string): ScanResult {
  const nucleiErr = r.errors.find((e) => e.startsWith('nuclei'))
  const zapErr = r.errors.find((e) => e.startsWith('zap'))
  const nuclei = r.nuclei ? parseNucleiOutput(r.nuclei) : []
  let zap: ReturnType<typeof parseZapReport> = []
  let zapParseErr: string | undefined
  if (r.zap) {
    try {
      zap = parseZapReport(r.zap)
    } catch {
      zapParseErr = 'ZAP report could not be read (it may have been truncated).'
    }
  }
  const findings = [...nuclei, ...zap].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
  const dur = Math.max(0, new Date(r.finishedAt).getTime() - new Date(r.startedAt).getTime())
  const checks: CheckRun[] = [
    { id: 'nuclei', name: 'Nuclei (Oracle agent)', status: nucleiErr ? 'error' : nuclei.some((f) => f.severity !== 'info') ? 'issues' : 'ok', note: nucleiErr, durationMs: dur },
    {
      id: 'zap',
      name: 'ZAP baseline (Oracle agent)',
      status: zapErr || zapParseErr ? 'error' : zap.some((f) => f.severity !== 'info') ? 'issues' : 'ok',
      note: zapErr ?? zapParseErr,
      durationMs: 0
    }
  ]
  return {
    id: `oci-${r.id}`,
    domainId,
    host: r.site,
    startedAt: r.startedAt,
    finishedAt: r.finishedAt,
    ...score(findings),
    findings,
    checks,
    origin: 'oracle'
  }
}

export async function importResults(): Promise<number> {
  if (!agentConfig()) return 0
  let since = store.get<number>(LAST_IMPORTED) ?? 0
  let imported = 0
  for (let page = 0; page < 20; page++) {
    const { results } = await call<{ results: RemoteResult[] }>('GET', `/api/vm/results?since=${since}`)
    if (!results.length) break
    for (const r of results) {
      const d = store.domains().find((x) => x.host === r.site)
      if (d && !store.scan(`oci-${r.id}`)) {
        store.addScan(toScanResult(r, d.id))
        imported++
      }
      since = Math.max(since, r.id)
    }
    store.set(LAST_IMPORTED, since)
  }
  return imported
}
