import { useEffect, useState } from 'react'
import type { CspCheck } from '../../../shared/types'
import { copy, errMsg } from '../util'

interface Props {
  domainId: string
  snippet: string
  /** Called after a Cloudflare change so the parent can refresh its change history. */
  onChanged: () => void
}

function CodeBox({ code }: { code: string }): React.JSX.Element {
  return (
    <div className="code">
      <pre>{code}</pre>
      <button className="ghost small" onClick={() => copy(code)}>
        Copy
      </button>
    </div>
  )
}

export default function CspHelper({ domainId, snippet, onChanged }: Props): React.JSX.Element {
  const [check, setCheck] = useState<CspCheck | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [tab, setTab] = useState(0)

  async function run(fn: () => Promise<void>): Promise<void> {
    setBusy(true)
    setError('')
    setMsg('')
    try {
      await fn()
    } catch (e) {
      setError(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  const recheck = (): Promise<void> => run(async () => setCheck(await window.sitewarden.cspCheck(domainId)))

  useEffect(() => {
    void recheck()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domainId])

  const fix = (): Promise<void> =>
    run(async () => {
      if (
        !confirm(
          "Cloudflare will replace your site's Content-Security-Policy header with the updated copy shown here, on every page of this host.\n\n" +
            'If some pages send a different policy, or you change your policy later, update it on your server instead and remove this override (Revert in the change history).'
        )
      )
        return
      const r = await window.sitewarden.cspFix(domainId)
      setCheck(r.check)
      if (r.result.ok) setMsg(r.check.status === 'allowed' ? 'Fixed. Your CSP now allows the guard.' : `${r.result.message} It can take a minute to show up; click Check again.`)
      else setError(r.result.message)
      onChanged()
    })

  if (!check) return <p className="small muted">{busy ? "Checking your site's Content-Security-Policy…" : error}</p>

  const policy = check.headerPatched ?? check.metaPatched ?? ''
  const nonceTag = snippet.replace('<script ', '<script nonce="YOUR-PAGE-NONCE" ')
  const ways: { label: string; body: React.JSX.Element }[] = []
  if (check.headerPatched) {
    ways.push(
      {
        label: 'Nginx',
        body: (
          <>
            <p className="small">Replace your existing Content-Security-Policy line with:</p>
            <CodeBox code={`add_header Content-Security-Policy "${check.headerPatched}" always;`} />
          </>
        )
      },
      {
        label: 'Apache',
        body: (
          <>
            <p className="small">In your vhost or .htaccess, replace the existing line with:</p>
            <CodeBox code={`Header always set Content-Security-Policy "${check.headerPatched}"`} />
          </>
        )
      },
      {
        label: 'Plugin / host panel',
        body: (
          <>
            <p className="small">
              If a security plugin (WordPress, Shopify app, etc.) or your hosting panel sets the policy, open its "security headers" or "CSP" setting
              and paste this as the new value:
            </p>
            <CodeBox code={check.headerPatched} />
          </>
        )
      }
    )
  }
  if (check.metaPatched) {
    ways.push({
      label: 'HTML meta tag',
      body: (
        <>
          <p className="small">Your page sets the policy in a &lt;meta&gt; tag. Replace it in your template with:</p>
          <CodeBox code={`<meta http-equiv="Content-Security-Policy" content="${check.metaPatched.replace(/"/g, '&quot;')}">`} />
        </>
      )
    })
  }
  const active = ways[Math.min(tab, ways.length - 1)]

  return (
    <div className="csp">
      <div className="row">
        <h4 className="spacer">Will your site's security policy (CSP) allow the guard?</h4>
        <button className="ghost small" onClick={recheck} disabled={busy}>
          {busy ? 'Checking…' : 'Check again'}
        </button>
      </div>
      {error && <div className="error small">{error}</div>}
      {msg && <div className="notice small">{msg}</div>}

      {check.status === 'error' && <div className="notice-warn small">{check.error}</div>}
      {check.status === 'none' && (
        <p className="small">
          <span className="pill ok">ready</span> Your homepage doesn't send a Content-Security-Policy, so the guard will load as is.
        </p>
      )}
      {check.status === 'allowed' && (
        <p className="small">
          <span className="pill ok">ready</span> Your CSP already allows <code>{check.workerOrigin}</code>.
        </p>
      )}

      {(check.status === 'blocked' || check.status === 'nonce') && (
        <>
          <p className="small">
            <span className="pill sev-high">blocked</span> Your CSP ({[check.inHeader && 'response header', check.inMeta && 'meta tag'].filter(Boolean).join(' and ')})
            would stop the guard:
          </p>
          <ul className="steps small">
            {check.problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>

          {check.canAutoFix && (
            <div className="autofix">
              <div>
                <b>Easiest: fix it with Cloudflare</b>
                <div className="small muted">
                  Adds <code>{check.workerOrigin}</code> to your policy at Cloudflare's edge. Nothing else in the policy changes, and you can revert it
                  from the change history.
                </div>
              </div>
              <button onClick={fix} disabled={busy}>
                Fix with Cloudflare
              </button>
            </div>
          )}
          {!check.canAutoFix && check.autoFixNote && <p className="small muted">{check.autoFixNote}</p>}

          {check.status === 'nonce' && (
            <>
              <p className="small">
                Your policy uses <code>'strict-dynamic'</code>, so the guard tag needs the same nonce your other script tags use. In your template, add it
                like this:
              </p>
              <CodeBox code={nonceTag} />
            </>
          )}

          {ways.length > 0 && policy && (
            <>
              <p className="small">
                <b>{check.canAutoFix ? 'Or update it where you set it:' : 'Update it where you set it:'}</b> the updated policy keeps everything you
                have and adds <code>{check.workerOrigin}</code>.
              </p>
              <div className="tabs" role="tablist">
                {ways.map((w, i) => (
                  <button key={w.label} role="tab" aria-selected={w === active} className={w === active ? 'active' : ''} onClick={() => setTab(i)}>
                    {w.label}
                  </button>
                ))}
              </div>
              {active?.body}
              <details>
                <summary className="small">Compare with your current policy</summary>
                <p className="small muted">Current:</p>
                <pre className="evidence">{check.header ?? check.meta}</pre>
                <p className="small muted">Updated:</p>
                <pre className="evidence">{policy}</pre>
              </details>
            </>
          )}
        </>
      )}
      {check.reportOnly && (
        <p className="small muted">You also send a Content-Security-Policy-Report-Only header. It only reports and never blocks, so it doesn't affect the guard.</p>
      )}
    </div>
  )
}
