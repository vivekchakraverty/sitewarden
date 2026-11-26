// OWASP ZAP baseline: spider + passive scan only (no attacks), driven by ZAP's Automation Framework.
// Each run uses a throwaway ZAP home folder and a random port so it never touches the user's own ZAP setup.
import { app } from 'electron'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'fs'
import { createServer } from 'net'
import { join } from 'path'
import type { Finding, Severity } from '../../shared/types'
import { USER_AGENT } from '../http'
import { findJava, run, settings, zapInfo } from '../tools/manager'
import type { Check } from './types'

/** ZAP passive rules our own checks already cover (headers, cookies, version leaks). */
export const ZAP_DUPLICATE_RULES = new Set(['10010', '10011', '10020', '10021', '10035', '10036', '10037', '10038', '10054', '10063'])

const RISK: Record<string, Severity> = { '3': 'high', '2': 'medium', '1': 'low', '0': 'info' }

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer()
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      srv.close(() => resolve(port))
    })
  })
}

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

export function zapPlan(host: string, reportDir: string, spiderMinutes: number): string {
  const plan = {
    env: {
      contexts: [
        {
          name: 'target',
          urls: [`https://${host}/`],
          includePaths: [`https?://(www\\.)?${esc(host)}([/?#:].*)?`]
        }
      ],
      parameters: { failOnError: false, failOnWarning: false, progressToStdout: true }
    },
    jobs: [
      { type: 'passiveScan-config', parameters: { maxAlertsPerRule: 10, scanOnlyInScope: true } },
      { type: 'spider', parameters: { context: 'target', maxDuration: spiderMinutes, maxDepth: 5, maxChildren: 30 } },
      { type: 'passiveScan-wait', parameters: { maxDuration: 5 } },
      {
        type: 'report',
        parameters: { template: 'traditional-json', reportDir, reportFile: 'zap-report', reportTitle: `SiteWarden baseline: ${host}` },
        risks: ['info', 'low', 'medium', 'high'],
        confidences: ['low', 'medium', 'high', 'confirmed']
      }
    ]
  }
  return JSON.stringify(plan, null, 2) // JSON is valid YAML
}

const stripHtml = (s?: string): string =>
  (s ?? '')
    .replace(/<\/p>\s*<p>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .trim()

interface ZapAlert {
  pluginid: string
  alertRef?: string
  alert?: string
  name?: string
  riskcode: string
  confidence: string
  desc?: string
  solution?: string
  reference?: string
  cweid?: string
  instances?: { uri?: string; method?: string; param?: string; evidence?: string }[]
  count?: string
}

export function parseZapReport(json: string): Finding[] {
  const report = JSON.parse(json) as { site?: { alerts?: ZapAlert[] }[] }
  const out: Finding[] = []
  for (const site of report.site ?? []) {
    for (const a of site.alerts ?? []) {
      if (a.confidence === '0') continue // marked false positive
      if (ZAP_DUPLICATE_RULES.has(String(a.pluginid))) continue
      const inst = (a.instances ?? []).slice(0, 5)
      const title = a.alert || a.name || `ZAP rule ${a.pluginid}`
      out.push({
        checkId: `zap.${a.alertRef || a.pluginid}`,
        severity: RISK[a.riskcode] ?? 'info',
        title: `${title}${a.count && Number(a.count) > 1 ? ` (${a.count} places)` : ''}`,
        detail: stripHtml(a.desc).slice(0, 1500) || 'Reported by the ZAP passive scanner.',
        evidence: inst.map((i) => [i.method, i.uri, i.param && `param: ${i.param}`, i.evidence && `evidence: ${i.evidence.slice(0, 120)}`].filter(Boolean).join(' ')).join('\n') || undefined,
        remediation: stripHtml(a.solution) || undefined,
        references: stripHtml(a.reference)
          .split(/\s+/)
          .filter((u) => /^https:\/\//.test(u))
          .slice(0, 5),
        source: 'zap'
      })
    }
  }
  return out
}

export const zapCheck: Check = {
  id: 'zap',
  name: 'OWASP ZAP baseline (spider + passive)',
  async run(ctx) {
    const zap = zapInfo()
    if (!zap.found || !zap.dir || !zap.jar) return { skipped: 'OWASP ZAP was not found. Install it or choose its folder on the Scanners page.' }
    const java = await findJava()
    if (!java) return { skipped: 'ZAP needs Java 17+. Install the Java runtime on the Scanners page.' }
    const s = settings()
    const work = mkdtempSync(join(app.getPath('temp'), 'sitewarden-zap-'))
    try {
      const home = join(work, 'home')
      const planPath = join(work, 'plan.yaml')
      writeFileSync(planPath, zapPlan(ctx.host, work, s.zapSpiderMinutes))
      const port = await freePort()
      ctx.note('ZAP starting…')
      const args = [
        '-Xmx1g', '-jar', zap.jar,
        '-cmd', '-silent', '-dir', home, '-port', String(port),
        '-config', `connection.defaultUserAgent=${USER_AGENT} zap`,
        '-autorun', planPath
      ]
      const r = await run(java.path, args, {
        cwd: zap.dir,
        signal: ctx.signal,
        timeoutMs: s.zapMaxMinutes * 60_000,
        onStdout: (l) => {
          const m = /Job (\S+) (started|finished)|found (\d+) URLs|(\d+) alerts?/i.exec(l)
          if (m) ctx.note(`ZAP · ${l.trim().slice(0, 120)}`)
        }
      })
      if (ctx.signal.aborted) throw new Error('Cancelled')
      const reportPath = join(work, 'zap-report.json')
      if (!existsSync(reportPath)) {
        const tail = (r.stdout + r.stderr).trim().split(/\r?\n/).slice(-3).join(' ')
        throw new Error(`ZAP did not produce a report (exit ${r.code}). ${tail.slice(0, 300)}`)
      }
      return parseZapReport(readFileSync(reportPath, 'utf8'))
    } finally {
      rmSync(work, { recursive: true, force: true })
    }
  }
}
