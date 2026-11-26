// Probes a short list of well-known sensitive paths. Each hit must match a content signature,
// so "soft 404" pages that return 200 for everything are not reported.
import type { Finding, Severity } from '../../shared/types'
import { get } from '../http'
import type { Check } from './types'

interface Probe {
  path: string
  severity: Severity
  title: string
  detail: string
  fixId: string
  matches(body: string): boolean
}

const notHtml = (b: string): boolean => !/<html|<!doctype/i.test(b.slice(0, 500))

const PROBES: Probe[] = [
  {
    path: '/.git/HEAD',
    severity: 'critical',
    title: 'Git repository is publicly downloadable',
    detail: 'Attackers can rebuild your source code, history and any secrets committed to it.',
    fixId: 'block-dotfiles',
    matches: (b) => /^(ref: refs\/|[0-9a-f]{40}\s*$)/.test(b.trim())
  },
  {
    path: '/.env',
    severity: 'critical',
    title: '.env file is publicly readable',
    detail: 'Environment files usually hold database passwords and API keys. Rotate every secret in it.',
    fixId: 'block-dotfiles',
    matches: (b) => notHtml(b) && /^[A-Z_][A-Z0-9_]*\s*=/m.test(b)
  },
  {
    path: '/wp-config.php.bak',
    severity: 'critical',
    title: 'WordPress config backup is publicly readable',
    detail: 'It contains database credentials and secret keys. Delete it and rotate the credentials.',
    fixId: 'remove-backups',
    matches: (b) => /DB_PASSWORD/.test(b)
  },
  {
    path: '/wp-config.php~',
    severity: 'critical',
    title: 'WordPress config editor backup is publicly readable',
    detail: 'It contains database credentials and secret keys. Delete it and rotate the credentials.',
    fixId: 'remove-backups',
    matches: (b) => /DB_PASSWORD/.test(b)
  },
  {
    path: '/backup.sql',
    severity: 'critical',
    title: 'Database dump is publicly downloadable',
    detail: 'Database dumps contain user data and password hashes.',
    fixId: 'remove-backups',
    matches: (b) => notHtml(b) && /(CREATE TABLE|INSERT INTO)/i.test(b)
  },
  {
    path: '/dump.sql',
    severity: 'critical',
    title: 'Database dump is publicly downloadable',
    detail: 'Database dumps contain user data and password hashes.',
    fixId: 'remove-backups',
    matches: (b) => notHtml(b) && /(CREATE TABLE|INSERT INTO)/i.test(b)
  },
  {
    path: '/.htpasswd',
    severity: 'high',
    title: '.htpasswd file is publicly readable',
    detail: 'Password hashes can be cracked offline.',
    fixId: 'block-dotfiles',
    matches: (b) => notHtml(b) && /^[\w.-]+:(\$|\{SHA\})/m.test(b)
  },
  {
    path: '/phpinfo.php',
    severity: 'high',
    title: 'phpinfo() page is public',
    detail: 'It reveals server paths, module versions and sometimes environment secrets.',
    fixId: 'remove-debug-pages',
    matches: (b) => /<title>PHP \d|phpinfo\(\)/i.test(b)
  },
  {
    path: '/info.php',
    severity: 'high',
    title: 'phpinfo() page is public',
    detail: 'It reveals server paths, module versions and sometimes environment secrets.',
    fixId: 'remove-debug-pages',
    matches: (b) => /<title>PHP \d|phpinfo\(\)/i.test(b)
  },
  {
    path: '/server-status',
    severity: 'medium',
    title: 'Apache server-status page is public',
    detail: 'It shows live requests, client IPs and internal URLs.',
    fixId: 'remove-debug-pages',
    matches: (b) => /Apache Server Status/i.test(b)
  },
  {
    path: '/.DS_Store',
    severity: 'low',
    title: '.DS_Store file is public',
    detail: 'It lists file and folder names, which can reveal hidden paths.',
    fixId: 'block-dotfiles',
    matches: (b) => b.includes('Bud1')
  }
]

async function pool<T, R>(items: T[], size: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = []
  let i = 0
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++
        out[idx] = await fn(items[idx])
      }
    })
  )
  return out
}

export const exposureCheck: Check = {
  id: 'exposure',
  name: 'Exposed sensitive files',
  async run(ctx) {
    const hits = await pool(PROBES, 3, async (p): Promise<Finding | null> => {
      try {
        const r = await get(`https://${ctx.host}${p.path}`, { redirect: 'manual', timeoutMs: 10000, maxBytes: 20000 })
        if (r.status !== 200 || !p.matches(r.body)) return null
        return {
          checkId: `exposure${p.path.replace(/[^\w]+/g, '.')}`,
          severity: p.severity,
          title: p.title,
          detail: p.detail,
          evidence: `https://${ctx.host}${p.path} returned 200`,
          fixId: p.fixId
        }
      } catch {
        return null
      }
    })
    const findings = hits.filter((h): h is Finding => h !== null)

    try {
      const r = await get(`https://${ctx.host}/.well-known/security.txt`, { redirect: 'follow', timeoutMs: 8000, maxBytes: 20000 })
      if (r.status !== 200 || !/^Contact:/im.test(r.body)) {
        findings.push({
          checkId: 'exposure.security-txt',
          severity: 'info',
          title: 'No security.txt',
          detail: 'A security.txt file tells researchers how to report vulnerabilities to you.',
          fixId: 'security-txt'
        })
      }
    } catch {
      // ignore
    }
    return findings
  }
}
