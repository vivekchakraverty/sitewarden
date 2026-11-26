// Exports a scan as a standalone HTML report.
import type { ScanResult } from '../shared/types'
import { getFix } from './fixes'

const esc = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

export function renderReport(scan: ScanResult): string {
  const rows = scan.findings
    .map((f) => {
      const fix = f.fixId ? getFix(f.fixId) : null
      const steps = fix
        ? fix.steps
            .map((s) => `<h4>${esc(s.platform)}</h4>${s.text ? `<p>${esc(s.text)}</p>` : ''}${s.code ? `<pre>${esc(s.code)}</pre>` : ''}`)
            .join('')
        : ''
      return `<section class="f ${f.severity}">
  <div class="sev">${f.severity}${f.source ? ` · ${f.source}` : ''}</div>
  <h3>${esc(f.title)}</h3>
  <p>${esc(f.detail)}</p>
  ${f.evidence ? `<pre class="ev">${esc(f.evidence)}</pre>` : ''}
  ${fix ? `<details><summary>How to fix: ${esc(fix.title)}</summary><p>${esc(fix.why)}</p>${steps}</details>` : ''}
  ${!fix && (f.remediation || f.references?.length) ? `<details><summary>How to fix</summary>${f.remediation ? `<p>${esc(f.remediation)}</p>` : ''}${(f.references ?? []).map((r) => `<p><a href="${esc(r)}">${esc(r)}</a></p>`).join('')}</details>` : ''}
</section>`
    })
    .join('\n')
  const checks = scan.checks
    .map((c) => `<tr><td>${esc(c.name)}</td><td>${c.status}</td><td>${esc(c.note ?? '')}</td></tr>`)
    .join('')
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SiteWarden report: ${esc(scan.host)}</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1b1f24;background:#fff}
h1{margin-bottom:.2rem}.meta{color:#5b6470}.grade{font-size:2.4rem;font-weight:700}
.f{border:1px solid #d8dde3;border-left-width:5px;border-radius:6px;padding:.6rem 1rem;margin:.8rem 0}
.critical{border-left-color:#c62828}.high{border-left-color:#ef6c00}.medium{border-left-color:#f9a825}.low{border-left-color:#1e88e5}.info{border-left-color:#90a4ae}
.sev{text-transform:uppercase;font-size:.75rem;font-weight:700;color:#5b6470}
h3{margin:.2rem 0}pre{background:#f3f5f7;padding:.6rem;border-radius:4px;overflow:auto;white-space:pre-wrap}
table{border-collapse:collapse;width:100%}td{border-bottom:1px solid #e3e7eb;padding:.3rem .4rem;vertical-align:top}
</style></head><body>
<h1>${esc(scan.host)}</h1>
<div class="meta">Scanned ${new Date(scan.startedAt).toLocaleString()} by SiteWarden</div>
<p><span class="grade">${scan.grade}</span> &nbsp; score ${scan.score}/100 &middot; ${scan.findings.length} finding(s)</p>
${rows || '<p>No issues found.</p>'}
<h2>Checks run</h2><table>${checks}</table>
<p class="meta">This report covers what can be seen from outside the server. It does not replace a file-level malware scan or a full penetration test.</p>
</body></html>`
}
