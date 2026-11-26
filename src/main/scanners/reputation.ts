// Malware and blacklist checks using the user's own API keys.
import type { Finding } from '../../shared/types'
import { USER_AGENT } from '../http'
import type { Check } from './types'

const TIMEOUT = 15000

export const safeBrowsingCheck: Check = {
  id: 'reputation.safebrowsing',
  name: 'Google Safe Browsing',
  async run(ctx) {
    const key = ctx.key('safeBrowsing')
    if (!key) return { skipped: 'Add a Google Safe Browsing key in Settings to enable this check.' }
    const urls = [`https://${ctx.host}/`, `http://${ctx.host}/`]
    if (ctx.home) urls.push(ctx.home.url)
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      signal: AbortSignal.timeout(TIMEOUT),
      headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
      body: JSON.stringify({
        client: { clientId: 'sitewarden', clientVersion: '0.1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [...new Set(urls)].map((url) => ({ url }))
        }
      })
    })
    if (!res.ok) throw new Error(`Safe Browsing returned HTTP ${res.status}${res.status === 400 || res.status === 403 ? ' (check the key and that the API is enabled)' : ''}`)
    const data = (await res.json()) as { matches?: { threatType: string; threat: { url: string } }[] }
    if (!data.matches?.length) return []
    const types = [...new Set(data.matches.map((m) => m.threatType))]
    return [
      {
        checkId: 'reputation.safebrowsing',
        severity: 'critical',
        title: `Google Safe Browsing flags this site (${types.join(', ')})`,
        detail: 'Chrome, Firefox and Safari show a red warning page to visitors. The site is probably compromised.',
        evidence: data.matches.map((m) => `${m.threatType}: ${m.threat.url}`).join('\n'),
        fixId: 'malware-cleanup'
      }
    ]
  }
}

export const virusTotalCheck: Check = {
  id: 'reputation.virustotal',
  name: 'VirusTotal domain reputation',
  async run(ctx) {
    const key = ctx.key('virusTotal')
    if (!key) return { skipped: 'Add a VirusTotal key in Settings to enable this check.' }
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ctx.host)}`, {
      signal: AbortSignal.timeout(TIMEOUT),
      headers: { 'x-apikey': key, 'User-Agent': USER_AGENT }
    })
    if (res.status === 404) return []
    if (res.status === 429) throw new Error('VirusTotal rate limit reached (free API: about 4 requests a minute). Try again shortly.')
    if (!res.ok) throw new Error(`VirusTotal returned HTTP ${res.status}${res.status === 401 ? ' (check the key)' : ''}`)
    const data = (await res.json()) as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number } } }
    }
    const s = data.data?.attributes?.last_analysis_stats ?? {}
    const malicious = s.malicious ?? 0
    const suspicious = s.suspicious ?? 0
    if (!malicious && !suspicious) return []
    const total = malicious + suspicious + (s.harmless ?? 0) + (s.undetected ?? 0)
    const f: Finding = {
      checkId: 'reputation.virustotal',
      severity: malicious >= 2 ? 'critical' : malicious === 1 ? 'high' : 'medium',
      title: `${malicious} security vendor(s) flag this domain as malicious${suspicious ? `, ${suspicious} as suspicious` : ''}`,
      detail:
        malicious >= 2
          ? 'Several vendors agree, so the site is likely serving malware or phishing. Clean it up, then request re-review from each vendor.'
          : 'A single detection is sometimes a false positive. Check the vendor details on VirusTotal and scan your files.',
      evidence: `${malicious + suspicious}/${total} engines. https://www.virustotal.com/gui/domain/${ctx.host}`,
      fixId: 'malware-cleanup'
    }
    return [f]
  }
}

export const urlhausCheck: Check = {
  id: 'reputation.urlhaus',
  name: 'URLhaus malware URLs',
  async run(ctx) {
    const key = ctx.key('urlhaus')
    if (!key) return { skipped: 'Add an abuse.ch Auth-Key in Settings to enable this check.' }
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      signal: AbortSignal.timeout(TIMEOUT),
      headers: { 'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': USER_AGENT },
      body: new URLSearchParams({ host: ctx.host }).toString()
    })
    if (!res.ok) throw new Error(`URLhaus returned HTTP ${res.status}${res.status === 401 ? ' (check the Auth-Key)' : ''}`)
    const data = (await res.json()) as { query_status: string; urls?: { url: string; url_status: string; threat?: string }[] }
    if (data.query_status !== 'ok' || !data.urls?.length) return []
    const online = data.urls.filter((u) => u.url_status === 'online')
    return [
      {
        checkId: 'reputation.urlhaus',
        severity: online.length ? 'critical' : 'medium',
        title: online.length
          ? `URLhaus lists ${online.length} live malware URL(s) on this host`
          : `URLhaus has ${data.urls.length} past (now offline) malware URL(s) on this host`,
        detail: online.length
          ? 'Your server is distributing malware right now. Take the files down and find how they got there.'
          : 'The listed files are gone, but the way they were planted may still be open.',
        evidence: (online.length ? online : data.urls)
          .slice(0, 5)
          .map((u) => `${u.url_status}: ${u.url}${u.threat ? ` (${u.threat})` : ''}`)
          .join('\n'),
        fixId: 'malware-cleanup'
      }
    ]
  }
}
