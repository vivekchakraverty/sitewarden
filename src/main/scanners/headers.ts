// Security response headers and information leakage.
import type { Finding } from '../../shared/types'
import type { Check } from './types'

export const headersCheck: Check = {
  id: 'headers',
  name: 'Security headers',
  async run(ctx) {
    if (!ctx.home) return { skipped: `Homepage could not be loaded: ${ctx.homeError ?? 'unknown error'}` }
    const h = ctx.home.headers
    const f: Finding[] = []

    const hsts = h.get('strict-transport-security')
    if (!hsts) {
      f.push({
        checkId: 'headers.hsts',
        severity: 'medium',
        title: 'Strict-Transport-Security (HSTS) is missing',
        detail: 'Without HSTS, browsers can be tricked into loading the site over plain HTTP.',
        fixId: 'header-hsts'
      })
    } else {
      const maxAge = Number(/max-age\s*=\s*(\d+)/i.exec(hsts)?.[1] ?? 0)
      if (maxAge < 15_552_000) {
        f.push({
          checkId: 'headers.hsts-short',
          severity: 'low',
          title: 'HSTS max-age is shorter than 6 months',
          detail: 'A longer max-age gives returning visitors lasting protection.',
          evidence: hsts,
          fixId: 'header-hsts'
        })
      }
    }

    const csp = h.get('content-security-policy')
    if (!csp) {
      f.push({
        checkId: 'headers.csp',
        severity: 'medium',
        title: 'Content-Security-Policy is missing',
        detail: 'A CSP limits where scripts can load from and is the main defence against XSS and injected skimmers.',
        fixId: 'header-csp'
      })
    } else if (/script-src[^;]*'unsafe-inline'/i.test(csp) && !/'nonce-|'sha(256|384|512)-/i.test(csp)) {
      f.push({
        checkId: 'headers.csp-unsafe-inline',
        severity: 'low',
        title: "CSP allows 'unsafe-inline' scripts",
        detail: "'unsafe-inline' removes most of the protection a CSP gives against XSS.",
        evidence: csp.slice(0, 300),
        fixId: 'header-csp'
      })
    }

    if (!h.get('x-content-type-options')?.toLowerCase().includes('nosniff')) {
      f.push({
        checkId: 'headers.nosniff',
        severity: 'low',
        title: 'X-Content-Type-Options: nosniff is missing',
        detail: 'Stops browsers from guessing file types, which can turn uploads into scripts.',
        fixId: 'header-nosniff'
      })
    }

    if (!h.get('x-frame-options') && !/frame-ancestors/i.test(csp ?? '')) {
      f.push({
        checkId: 'headers.framing',
        severity: 'medium',
        title: 'Page can be embedded in other sites (clickjacking)',
        detail: "Neither X-Frame-Options nor CSP frame-ancestors is set.",
        fixId: 'header-framing'
      })
    }

    if (!h.get('referrer-policy')) {
      f.push({
        checkId: 'headers.referrer',
        severity: 'low',
        title: 'Referrer-Policy is missing',
        detail: 'Full URLs (which can contain tokens or IDs) may be sent to third-party sites.',
        fixId: 'header-referrer'
      })
    }

    if (!h.get('permissions-policy')) {
      f.push({
        checkId: 'headers.permissions',
        severity: 'info',
        title: 'Permissions-Policy is not set',
        detail: 'Optional: restricts camera, microphone, geolocation and similar features for embedded content.',
        fixId: 'header-permissions'
      })
    }

    const server = h.get('server') ?? ''
    if (/\d/.test(server)) {
      f.push({
        checkId: 'headers.server-version',
        severity: 'low',
        title: 'Server header reveals software version',
        detail: 'Version numbers help attackers match known exploits.',
        evidence: `Server: ${server}`,
        fixId: 'hide-versions'
      })
    }
    const powered = h.get('x-powered-by')
    if (powered) {
      f.push({
        checkId: 'headers.powered-by',
        severity: 'low',
        title: 'X-Powered-By header reveals the technology stack',
        detail: 'Remove it so the stack and version are not advertised.',
        evidence: `X-Powered-By: ${powered}`,
        fixId: 'hide-versions'
      })
    }

    return f
  }
}

export const cookiesCheck: Check = {
  id: 'cookies',
  name: 'Cookie flags',
  async run(ctx) {
    if (!ctx.home) return { skipped: 'Homepage could not be loaded.' }
    const f: Finding[] = []
    for (const raw of ctx.home.setCookies) {
      const name = raw.split('=')[0].trim()
      const attrs = raw.toLowerCase()
      const missing: string[] = []
      if (!/;\s*secure/.test(attrs)) missing.push('Secure')
      if (!/;\s*httponly/.test(attrs) && /sess|auth|token|sid|login/i.test(name)) missing.push('HttpOnly')
      if (!/;\s*samesite=/.test(attrs)) missing.push('SameSite')
      if (missing.length) {
        f.push({
          checkId: 'cookies.flags',
          severity: missing.includes('Secure') || missing.includes('HttpOnly') ? 'medium' : 'low',
          title: `Cookie "${name}" is missing ${missing.join(', ')}`,
          detail: 'Cookie flags stop cookies leaking over HTTP, to scripts, or in cross-site requests.',
          evidence: raw.split(';').slice(1).join(';').trim() || '(no attributes)',
          fixId: 'cookie-flags'
        })
      }
    }
    return f
  }
}
