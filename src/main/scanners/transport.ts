// HTTPS availability, HTTP->HTTPS redirect and certificate health.
import tls from 'tls'
import type { Finding } from '../../shared/types'
import { get } from '../http'
import type { Check } from './types'

interface CertInfo {
  authorized: boolean
  authError?: string
  protocol: string | null
  validTo: Date
  issuer: string
  altNames: string
}

function inspectCert(host: string): Promise<CertInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 10000 })
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate()
      resolve({
        authorized: socket.authorized,
        authError: socket.authorizationError ? String(socket.authorizationError) : undefined,
        protocol: socket.getProtocol(),
        validTo: new Date(cert.valid_to),
        issuer: String(cert.issuer?.O ?? cert.issuer?.CN ?? 'unknown'),
        altNames: cert.subjectaltname ?? ''
      })
      socket.end()
    })
    socket.once('timeout', () => {
      socket.destroy()
      reject(new Error('TLS connection timed out'))
    })
    socket.once('error', reject)
  })
}

export const transportCheck: Check = {
  id: 'transport',
  name: 'HTTPS and certificate',
  async run(ctx) {
    const findings: Finding[] = []

    try {
      const c = await inspectCert(ctx.host)
      const daysLeft = Math.floor((c.validTo.getTime() - Date.now()) / 86_400_000)
      if (!c.authorized) {
        findings.push({
          checkId: 'transport.cert-invalid',
          severity: 'critical',
          title: 'TLS certificate is not trusted',
          detail: 'Browsers will show a security warning to visitors.',
          evidence: c.authError,
          fixId: 'tls-certificate'
        })
      }
      if (daysLeft < 0) {
        findings.push({
          checkId: 'transport.cert-expired',
          severity: 'critical',
          title: 'TLS certificate has expired',
          detail: `Expired on ${c.validTo.toDateString()}.`,
          fixId: 'tls-certificate'
        })
      } else if (daysLeft < 14) {
        findings.push({
          checkId: 'transport.cert-expiring',
          severity: 'high',
          title: `TLS certificate expires in ${daysLeft} days`,
          detail: `Issued by ${c.issuer}; valid until ${c.validTo.toDateString()}.`,
          fixId: 'tls-certificate'
        })
      }
      if (c.protocol && /^TLSv1(\.1)?$/.test(c.protocol)) {
        findings.push({
          checkId: 'transport.old-tls',
          severity: 'high',
          title: `Server negotiated an outdated protocol (${c.protocol})`,
          detail: 'TLS 1.0 and 1.1 are deprecated. Enable TLS 1.2 and 1.3 only.',
          fixId: 'tls-protocols'
        })
      }
    } catch (e) {
      findings.push({
        checkId: 'transport.no-https',
        severity: 'critical',
        title: 'HTTPS is not available',
        detail: 'Could not open a TLS connection on port 443.',
        evidence: (e as Error).message,
        fixId: 'tls-certificate'
      })
    }

    try {
      const res = await get(`http://${ctx.host}/`, { redirect: 'manual', timeoutMs: 10000, maxBytes: 10000 })
      const loc = res.headers.get('location') ?? ''
      const redirectsToHttps = res.status >= 300 && res.status < 400 && loc.startsWith('https://')
      if (!redirectsToHttps) {
        findings.push({
          checkId: 'transport.no-redirect',
          severity: 'medium',
          title: 'HTTP does not redirect to HTTPS',
          detail: 'Visitors who type the address without https:// get an unencrypted page.',
          evidence: `http://${ctx.host}/ returned ${res.status}${loc ? ` -> ${loc}` : ''}`,
          fixId: 'https-redirect'
        })
      }
    } catch {
      // Port 80 closed is acceptable when HSTS is in place; the headers check covers that.
    }

    return findings
  }
}
