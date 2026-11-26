// DNS hygiene: email spoofing protection (SPF, DMARC) and certificate issuance control (CAA).
import { promises as dns } from 'dns'
import type { Finding } from '../../shared/types'
import type { Check } from './types'

async function txt(name: string): Promise<string[]> {
  try {
    return (await dns.resolveTxt(name)).map((parts) => parts.join(''))
  } catch {
    return []
  }
}

/** Walks up the labels so www.example.com also finds records on example.com. */
async function firstWith<T>(host: string, fn: (name: string) => Promise<T | null>): Promise<{ name: string; value: T } | null> {
  const labels = host.split('.')
  for (let i = 0; i <= labels.length - 2; i++) {
    const name = labels.slice(i).join('.')
    const value = await fn(name)
    if (value !== null) return { name, value }
  }
  return null
}

export const dnsCheck: Check = {
  id: 'dns',
  name: 'DNS and email spoofing protection',
  async run(ctx) {
    const f: Finding[] = []
    const mx = await dns.resolveMx(ctx.host).catch(() => [])
    const sendsMail = mx.length > 0 && !(mx.length === 1 && mx[0].exchange === '')

    const spf = (await txt(ctx.host)).find((r) => /^v=spf1\b/i.test(r))
    if (!spf) {
      f.push({
        checkId: 'dns.spf',
        severity: sendsMail ? 'medium' : 'low',
        title: 'No SPF record',
        detail: sendsMail
          ? 'Without SPF, anyone can send email that claims to come from your domain.'
          : 'This domain does not receive mail. Publish "v=spf1 -all" so it cannot be used for spoofed email.',
        fixId: 'dns-spf'
      })
    } else if (/[+?]all\b/i.test(spf) || !/all\b/i.test(spf)) {
      f.push({
        checkId: 'dns.spf-weak',
        severity: /\+all/i.test(spf) ? 'high' : 'low',
        title: 'SPF record does not reject unknown senders',
        detail: 'End the record with "-all" (or "~all" while testing) so unlisted servers fail.',
        evidence: spf,
        fixId: 'dns-spf'
      })
    }

    const dmarc = await firstWith(ctx.host, async (name) => (await txt(`_dmarc.${name}`)).find((r) => /^v=DMARC1/i.test(r)) ?? null)
    if (!dmarc) {
      f.push({
        checkId: 'dns.dmarc',
        severity: sendsMail ? 'medium' : 'low',
        title: 'No DMARC policy',
        detail: 'DMARC tells mail providers what to do with messages that fail SPF/DKIM, and sends you reports.',
        fixId: 'dns-dmarc'
      })
    } else if (/\bp\s*=\s*none/i.test(dmarc.value)) {
      f.push({
        checkId: 'dns.dmarc-none',
        severity: 'low',
        title: 'DMARC policy is "none" (monitor only)',
        detail: 'Spoofed mail is still delivered. Move to p=quarantine, then p=reject, once reports look clean.',
        evidence: `_dmarc.${dmarc.name}: ${dmarc.value}`,
        fixId: 'dns-dmarc'
      })
    }

    const caa = await firstWith(ctx.host, async (name) => {
      const recs = await dns.resolveCaa(name).catch(() => [])
      return recs.length ? recs : null
    })
    if (!caa) {
      f.push({
        checkId: 'dns.caa',
        severity: 'info',
        title: 'No CAA record',
        detail: 'A CAA record limits which certificate authorities may issue certificates for your domain.',
        fixId: 'dns-caa'
      })
    }
    return f
  }
}
