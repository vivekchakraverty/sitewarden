// Runs ProjectDiscovery Nuclei against a verified domain with non-intrusive templates only.
import type { Finding, Severity } from '../../shared/types'
import { USER_AGENT } from '../http'
import { nucleiPath, run, settings, templatesDir } from '../tools/manager'
import type { Check } from './types'

/** Template tags that can harm a site or lock accounts; never run. */
export const EXCLUDED_TAGS = ['dos', 'fuzz', 'fuzzing', 'intrusive', 'bruteforce', 'brute-force', 'default-login', 'osint']

interface NucleiResult {
  'template-id': string
  info: {
    name: string
    severity: string
    description?: string
    remediation?: string
    reference?: string[] | string | null
    classification?: { 'cve-id'?: string[] | string | null }
    tags?: string[] | string
  }
  'matched-at'?: string
  host?: string
  'extracted-results'?: string[]
  'matcher-name'?: string
}

const SEV: Record<string, Severity> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info', unknown: 'info' }
const arr = (v: string[] | string | null | undefined): string[] => (Array.isArray(v) ? v : v ? String(v).split(/[\n,]\s*/) : []).filter(Boolean)

export function nucleiArgs(host: string, s = settings()): string[] {
  const args = [
    '-u', `https://${host}`,
    '-t', templatesDir(),
    '-jsonl', '-silent', '-nc', '-duc',
    '-severity', 'low,medium,high,critical',
    '-etags', EXCLUDED_TAGS.join(','),
    '-pt', 'http,ssl,dns',
    '-rl', String(s.nucleiRate),
    '-c', '10', '-timeout', '10', '-retries', '1',
    '-H', `User-Agent: ${USER_AGENT} nuclei`,
    '-stats', '-sj', '-si', '5'
  ]
  if (!s.nucleiInteractsh) args.push('-ni')
  return args
}

/** Turns Nuclei JSONL output into findings, merging repeats of the same template. */
export function parseNucleiOutput(jsonl: string): Finding[] {
  const byTemplate = new Map<string, { r: NucleiResult; hits: string[] }>()
  for (const line of jsonl.split(/\r?\n/)) {
    const t = line.trim()
    if (!t.startsWith('{')) continue
    let r: NucleiResult
    try {
      r = JSON.parse(t)
    } catch {
      continue
    }
    if (!r['template-id'] || !r.info) continue
    const hit = [r['matched-at'] ?? r.host, r['matcher-name'], ...(r['extracted-results'] ?? []).slice(0, 3)].filter(Boolean).join(' · ')
    const entry = byTemplate.get(r['template-id'])
    if (entry) {
      if (entry.hits.length < 10 && hit) entry.hits.push(hit)
    } else byTemplate.set(r['template-id'], { r, hits: hit ? [hit] : [] })
  }
  return [...byTemplate.values()].slice(0, 200).map(({ r, hits }) => {
    const cves = arr(r.info.classification?.['cve-id'])
    return {
      checkId: `nuclei.${r['template-id']}`,
      severity: SEV[(r.info.severity || 'info').toLowerCase()] ?? 'info',
      title: `${r.info.name}${cves.length ? ` (${cves.slice(0, 2).join(', ').toUpperCase()})` : ''}`,
      detail: (r.info.description || 'Detected by a Nuclei template.').trim().slice(0, 1500),
      evidence: hits.join('\n') || undefined,
      remediation: r.info.remediation?.trim() || undefined,
      references: arr(r.info.reference).filter((u) => /^https:\/\//.test(u)).slice(0, 5),
      source: 'nuclei'
    }
  })
}

export const nucleiCheck: Check = {
  id: 'nuclei',
  name: 'Nuclei vulnerability templates',
  async run(ctx) {
    const bin = nucleiPath()
    if (!bin) return { skipped: 'Nuclei is not installed. Install it on the Scanners page.' }
    const s = settings()
    let findings = 0
    ctx.note('Nuclei starting…')
    const r = await run(bin, nucleiArgs(ctx.host, s), {
      signal: ctx.signal,
      timeoutMs: s.nucleiMaxMinutes * 60_000,
      onStdout: (l) => {
        if (l.startsWith('{') && l.includes('"template-id"')) ctx.note(`Nuclei · ${++findings} finding(s) so far`)
      },
      onStderr: (l) => {
        // -stats -sj prints JSON progress lines
        if (!l.startsWith('{')) return
        try {
          const st = JSON.parse(l) as { percent?: string | number; requests?: string | number; total?: string | number }
          if (st.percent !== undefined) ctx.note(`Nuclei ${st.percent}% · ${st.requests ?? '?'} of ${st.total ?? '?'} requests · ${findings} finding(s)`)
        } catch {
          // ignore
        }
      }
    })
    if (ctx.signal.aborted) throw new Error('Cancelled')
    const out = parseNucleiOutput(r.stdout)
    if (r.code !== 0 && !out.length) {
      const msg = r.stderr.split(/\r?\n/).filter((l) => /FTL|ERR|error/i.test(l)).slice(-2).join(' ')
      throw new Error(`Nuclei exited with code ${r.code}${msg ? `: ${msg.slice(0, 300)}` : ''}`)
    }
    return out
  }
}
