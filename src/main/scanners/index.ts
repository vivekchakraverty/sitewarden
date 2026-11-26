// Runs every check against a verified domain and scores the result.
import { randomUUID } from 'crypto'
import type { CheckRun, DeepOptions, Finding, ScanProgress, ScanResult, Severity } from '../../shared/types'
import { assertVerified } from '../domains'
import { get } from '../http'
import { getKey } from '../secrets'
import { store } from '../store'
import { contentCheck } from './content'
import { dnsCheck } from './dnsmail'
import { exposureCheck } from './exposure'
import { cookiesCheck, headersCheck } from './headers'
import { safeBrowsingCheck, urlhausCheck, virusTotalCheck } from './reputation'
import { nucleiCheck } from './nuclei'
import { transportCheck } from './transport'
import { zapCheck } from './zap'
import type { Check, ScanContext } from './types'

export const CHECKS: Check[] = [
  transportCheck,
  headersCheck,
  cookiesCheck,
  contentCheck,
  exposureCheck,
  dnsCheck,
  safeBrowsingCheck,
  virusTotalCheck,
  urlhausCheck
]

const PENALTY: Record<Severity, number> = { critical: 30, high: 15, medium: 7, low: 2, info: 0 }
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export function score(findings: Finding[]): { score: number; grade: string } {
  const s = Math.max(0, 100 - findings.reduce((sum, f) => sum + PENALTY[f.severity], 0))
  const anyCritical = findings.some((f) => f.severity === 'critical')
  const grade = anyCritical ? 'F' : s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F'
  return { score: s, grade }
}

const running = new Map<string, AbortController>()

export function cancelScan(domainId: string): void {
  running.get(domainId)?.abort()
}

export async function runScan(
  domainId: string,
  onProgress: (p: ScanProgress) => void,
  deep: DeepOptions = { nuclei: false, zap: false }
): Promise<ScanResult> {
  if (running.has(domainId)) throw new Error('A scan of this domain is already running.')
  const controller = new AbortController()
  running.set(domainId, controller)
  try {
    const domain = await assertVerified(domainId)
    const startedAt = new Date().toISOString()
    const checks: CheckRun[] = []
    const list = [...CHECKS, ...(deep.nuclei ? [nucleiCheck] : []), ...(deep.zap ? [zapCheck] : [])]
    let done = 0
    let current = list[0]
    const ctx: ScanContext = {
      host: domain.host,
      key: getKey,
      signal: controller.signal,
      note: (text) => onProgress({ domainId, checkId: current.id, checkName: current.name, done, total: list.length, note: text })
    }
    try {
      ctx.home = await get(`https://${domain.host}/`)
    } catch (e) {
      ctx.homeError = (e as Error).message
    }

    const findings: Finding[] = []
    for (const check of list) {
      if (controller.signal.aborted) {
        checks.push({ id: check.id, name: check.name, status: 'skipped', note: 'Scan cancelled', durationMs: 0 })
        continue
      }
      current = check
      onProgress({ domainId, checkId: check.id, checkName: check.name, done, total: list.length })
      const t0 = Date.now()
      try {
        const out = await check.run(ctx)
        if (Array.isArray(out)) {
          findings.push(...out)
          checks.push({ id: check.id, name: check.name, status: out.some((f) => f.severity !== 'info') ? 'issues' : 'ok', durationMs: Date.now() - t0 })
        } else {
          checks.push({ id: check.id, name: check.name, status: 'skipped', note: out.skipped, durationMs: Date.now() - t0 })
        }
      } catch (e) {
        const cancelled = controller.signal.aborted
        checks.push({ id: check.id, name: check.name, status: cancelled ? 'skipped' : 'error', note: cancelled ? 'Scan cancelled' : (e as Error).message, durationMs: Date.now() - t0 })
      }
      done++
    }
    onProgress({ domainId, checkId: 'done', checkName: 'Done', done, total: list.length })

    findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    const result: ScanResult = {
      id: randomUUID(),
      domainId,
      host: domain.host,
      startedAt,
      finishedAt: new Date().toISOString(),
      ...score(findings),
      findings,
      checks
    }
    store.addScan(result)
    return result
  } finally {
    running.delete(domainId)
  }
}
