// Page content checks: outdated JS libraries, mixed content, missing Subresource Integrity, CMS disclosure.
import type { Finding, Severity } from '../../shared/types'
import { get } from '../http'
import type { Check } from './types'

interface LibRule {
  lib: string
  /** Patterns that capture a version from a script URL. */
  url: RegExp[]
  /** Patterns that capture a version from the script body. */
  body: RegExp[]
  /** Returns a reason if the version is vulnerable or end-of-life, else null. */
  assess(v: number[]): { severity: Severity; reason: string } | null
}

const lt = (a: number[], b: number[]): boolean => {
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0)
  }
  return false
}

const LIBS: LibRule[] = [
  {
    lib: 'jQuery',
    url: [/jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i, /jquery@(\d+\.\d+\.\d+)/i, /\/jquery(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)/i, /jquery\/(\d+\.\d+\.\d+)\/jquery/i],
    body: [/jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)/],
    assess: (v) =>
      lt(v, [3, 5, 0])
        ? { severity: 'medium', reason: 'Versions before 3.5.0 have XSS flaws in HTML handling (CVE-2020-11022, CVE-2020-11023).' }
        : null
  },
  {
    lib: 'jQuery UI',
    url: [/jquery-ui[.-](\d+\.\d+\.\d+)/i, /jqueryui\/(\d+\.\d+\.\d+)\//i, /jquery-ui(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)/i],
    body: [/jQuery UI - v(\d+\.\d+\.\d+)/],
    assess: (v) =>
      lt(v, [1, 13, 0])
        ? { severity: 'medium', reason: 'Versions before 1.13.0 have XSS flaws (CVE-2021-41182, -41183, -41184).' }
        : null
  },
  {
    lib: 'Bootstrap',
    url: [/bootstrap@(\d+\.\d+\.\d+)/i, /bootstrap\/(\d+\.\d+\.\d+)\//i, /bootstrap[.-](\d+\.\d+\.\d+)/i],
    body: [/Bootstrap v(\d+\.\d+\.\d+)/],
    assess: (v) =>
      (v[0] === 3 && lt(v, [3, 4, 1])) || (v[0] === 4 && lt(v, [4, 3, 1]))
        ? { severity: 'medium', reason: 'XSS in tooltip/popover data attributes (CVE-2019-8331).' }
        : v[0] <= 3
          ? { severity: 'low', reason: 'Bootstrap 3 is end-of-life and no longer gets security fixes.' }
          : null
  },
  {
    lib: 'AngularJS',
    url: [/angular(?:js)?[@/-](1\.\d+\.\d+)/i],
    body: [/AngularJS v(1\.\d+\.\d+)/],
    assess: () => ({ severity: 'medium', reason: 'AngularJS (1.x) reached end-of-life in January 2022 and has unpatched vulnerabilities.' })
  },
  {
    lib: 'Lodash',
    url: [/lodash@(\d+\.\d+\.\d+)/i, /lodash\.js\/(\d+\.\d+\.\d+)\//i],
    body: [],
    assess: (v) =>
      lt(v, [4, 17, 21]) ? { severity: 'medium', reason: 'Prototype pollution / command injection before 4.17.21 (CVE-2021-23337).' } : null
  },
  {
    lib: 'Moment.js',
    url: [/moment@(\d+\.\d+\.\d+)/i, /moment\.js\/(\d+\.\d+\.\d+)\//i],
    body: [/\/\/! moment\.js\s*\n\/\/! version : (\d+\.\d+\.\d+)/],
    assess: (v) =>
      lt(v, [2, 29, 4]) ? { severity: 'low', reason: 'ReDoS in RFC 2822 parsing before 2.29.4 (CVE-2022-31129).' } : null
  },
  {
    lib: 'Vue 2',
    url: [/vue@(2\.\d+\.\d+)/i, /vue\/(2\.\d+\.\d+)\//i],
    body: [/Vue\.js v(2\.\d+\.\d+)/],
    assess: () => ({ severity: 'low', reason: 'Vue 2 reached end-of-life on 31 Dec 2023.' })
  }
]

function attr(tag: string, name: string): string | undefined {
  const m = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)
  return m ? (m[2] ?? m[3] ?? m[4]) : undefined
}

function sameSite(a: string, b: string): boolean {
  const base = (h: string): string => h.split('.').slice(-2).join('.')
  return base(a) === base(b)
}

export const contentCheck: Check = {
  id: 'content',
  name: 'Page content and JavaScript libraries',
  async run(ctx) {
    if (!ctx.home) return { skipped: 'Homepage could not be loaded.' }
    const html = ctx.home.body
    const pageUrl = new URL(ctx.home.url)
    const f: Finding[] = []

    const scriptTags = html.match(/<script\b[^>]*>/gi) ?? []
    const scripts = scriptTags
      .map((t) => ({ tag: t, src: attr(t, 'src') }))
      .filter((s): s is { tag: string; src: string } => Boolean(s.src))
      .map((s) => {
        try {
          return { ...s, url: new URL(s.src, pageUrl) }
        } catch {
          return null
        }
      })
      .filter((s): s is { tag: string; src: string; url: URL } => s !== null)

    // --- Outdated libraries: match URLs first, then fetch up to 12 scripts and read banners.
    const found = new Map<string, { version: string; where: string }>()
    const record = (lib: string, version: string, where: string): void => {
      if (!found.has(lib)) found.set(lib, { version, where })
    }
    for (const s of scripts) {
      for (const rule of LIBS) {
        for (const re of rule.url) {
          const m = re.exec(s.url.href)
          if (m) record(rule.lib, m[1], s.url.href)
        }
      }
    }
    const toFetch = scripts.filter((s) => s.url.protocol === 'https:').slice(0, 12)
    await Promise.all(
      toFetch.map(async (s) => {
        try {
          const js = await get(s.url.href, { timeoutMs: 10000, maxBytes: 600_000 })
          const head = js.body.slice(0, 4000)
          for (const rule of LIBS) {
            for (const re of rule.body) {
              const m = re.exec(head) ?? re.exec(js.body)
              if (m) record(rule.lib, m[1], s.url.href)
            }
          }
        } catch {
          // unreachable script: ignore
        }
      })
    )
    for (const [lib, { version, where }] of found) {
      const rule = LIBS.find((r) => r.lib === lib)!
      const verdict = rule.assess(version.split('.').map(Number))
      if (verdict) {
        f.push({
          checkId: `content.lib.${lib.toLowerCase().replace(/\W+/g, '-')}`,
          severity: verdict.severity,
          title: `${lib} ${version} is outdated`,
          detail: verdict.reason,
          evidence: where,
          fixId: 'update-js-library'
        })
      }
    }

    // --- Mixed content on an HTTPS page.
    if (pageUrl.protocol === 'https:') {
      const active: string[] = []
      const passive: string[] = []
      for (const tag of html.match(/<(script|iframe|link|img|source|video|audio)\b[^>]*>/gi) ?? []) {
        const name = /^<(\w+)/.exec(tag)![1].toLowerCase()
        const url = attr(tag, name === 'link' ? 'href' : 'src')
        if (!url?.toLowerCase().startsWith('http://')) continue
        if (name === 'link' && !/stylesheet/i.test(attr(tag, 'rel') ?? '')) continue
        ;(['script', 'iframe', 'link'].includes(name) ? active : passive).push(url)
      }
      if (active.length) {
        f.push({
          checkId: 'content.mixed-active',
          severity: 'high',
          title: `${active.length} script/stylesheet/iframe loaded over plain HTTP`,
          detail: 'Anyone on the network path can replace these files and take over the page. Browsers usually block them, which also breaks the page.',
          evidence: active.slice(0, 5).join('\n'),
          fixId: 'mixed-content'
        })
      }
      if (passive.length) {
        f.push({
          checkId: 'content.mixed-passive',
          severity: 'low',
          title: `${passive.length} image/media file(s) loaded over plain HTTP`,
          detail: 'These can be swapped or tracked in transit and trigger "not fully secure" warnings.',
          evidence: passive.slice(0, 5).join('\n'),
          fixId: 'mixed-content'
        })
      }
    }

    // --- Third-party scripts without Subresource Integrity.
    const noSri = scripts.filter((s) => !sameSite(s.url.hostname, ctx.host) && !attr(s.tag, 'integrity'))
    if (noSri.length) {
      const hosts = [...new Set(noSri.map((s) => s.url.hostname))]
      f.push({
        checkId: 'content.sri',
        severity: 'low',
        title: `${noSri.length} third-party script(s) without Subresource Integrity`,
        detail: `If ${hosts.length === 1 ? 'that provider is' : 'any of these providers is'} compromised, the attacker's code runs on your site. SRI pins static files to a known hash. (Scripts that change often, like analytics tags, cannot use SRI; rely on CSP for those.)`,
        evidence: hosts.join(', '),
        fixId: 'sri'
      })
    }

    // --- CMS / generator disclosure.
    const gen = (html.match(/<meta\b[^>]*>/gi) ?? []).map((m) => (attr(m, 'name')?.toLowerCase() === 'generator' ? attr(m, 'content') : undefined)).find(Boolean)
    if (gen && /\d/.test(gen)) {
      f.push({
        checkId: 'content.generator',
        severity: 'low',
        title: `Page advertises its CMS version (${gen})`,
        detail: 'The generator tag tells attackers exactly which known vulnerabilities to try.',
        fixId: 'hide-generator'
      })
    }
    if (/<title>\s*Index of \//i.test(html)) {
      f.push({
        checkId: 'content.dir-listing',
        severity: 'medium',
        title: 'Directory listing is enabled on the homepage',
        detail: 'Visitors can browse every file in the folder.',
        fixId: 'directory-listing'
      })
    }

    return f
  }
}
