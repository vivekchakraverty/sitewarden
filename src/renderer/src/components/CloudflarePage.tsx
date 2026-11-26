import { useEffect, useState } from 'react'
import type { CfStatus, DeployResult } from '../../../shared/types'
import { errMsg } from '../util'

const PERMISSIONS: [string, string, string][] = [
  ['Account', 'Workers Scripts', 'Edit'],
  ['Account', 'D1', 'Edit'],
  ['Zone', 'Zone', 'Read'],
  ['Zone', 'Zone Settings', 'Edit'],
  ['Zone', 'Transform Rules', 'Edit'],
  ['Zone', 'Zone WAF', 'Edit'],
  ['Zone', 'Bot Management', 'Edit']
]

export default function CloudflarePage({ onChanged }: { onChanged: () => void }): React.JSX.Element {
  const [st, setSt] = useState<CfStatus | null>(null)
  const [tokenDraft, setTokenDraft] = useState('')
  const [accountId, setAccountId] = useState('')
  const [webhook, setWebhook] = useState('')
  const [copyKeys, setCopyKeys] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<DeployResult | null>(null)

  const load = async (): Promise<void> => {
    const s = await window.sitewarden.cfStatus()
    setSt(s)
    setAccountId(s.accountId ?? s.accounts[0]?.id ?? '')
  }
  useEffect(() => {
    void load()
  }, [])

  async function run(fn: () => Promise<void>): Promise<void> {
    setBusy(true)
    setError('')
    try {
      await fn()
    } catch (e) {
      setError(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  const connect = (): Promise<void> =>
    run(async () => {
      const s = await window.sitewarden.cfConnect(tokenDraft)
      setTokenDraft('')
      setSt(s)
      setAccountId(s.accountId ?? s.accounts[0]?.id ?? '')
    })

  const deploy = (): Promise<void> =>
    run(async () => {
      setResult(null)
      const r = await window.sitewarden.cfDeploy({ accountId, alertWebhook: webhook || undefined, copyKeys })
      setWebhook('')
      setResult(r)
      await load()
      onChanged()
    })

  const remove = (): Promise<void> =>
    run(async () => {
      if (!confirm('Delete the sitewarden-agent Worker from your Cloudflare account? Monitoring stops. The D1 database with history is kept; you can delete it in the Cloudflare dashboard.')) return
      await window.sitewarden.cfRemoveAgent()
      setResult(null)
      await load()
      onChanged()
    })

  const disconnect = (): Promise<void> =>
    run(async () => {
      if (!confirm('Forget the Cloudflare token on this computer? The deployed agent keeps running.')) return
      await window.sitewarden.cfDisconnect()
      await load()
    })

  if (!st) return <div className="page muted">Loading…</div>

  return (
    <div className="page">
      <h1>Cloudflare</h1>
      <p className="muted">
        Connect your own Cloudflare account (the free plan is enough). SiteWarden can then harden each site's Cloudflare settings and deploy a small
        monitoring agent into <b>your</b> account that runs 24/7, even when this app is closed.
      </p>
      {error && <div className="error">{error}</div>}

      <section className="card">
        <div className="row">
          <h3>1. API token</h3>
          <span className={`pill ${st.connected ? 'ok' : ''}`}>{st.connected ? 'Connected' : 'Not connected'}</span>
        </div>
        <p className="small muted">
          In Cloudflare go to My Profile &gt; API Tokens &gt; Create Token &gt; Create Custom Token, and add these permissions. Under Zone Resources
          you can limit it to the sites you add here.
        </p>
        <table className="checks small">
          <tbody>
            {PERMISSIONS.map(([scope, perm, level]) => (
              <tr key={perm}>
                <td>{scope}</td>
                <td>{perm}</td>
                <td>{level}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="small muted">
          <a
            href="https://dash.cloudflare.com/profile/api-tokens"
            onClick={(e) => {
              e.preventDefault()
              void window.sitewarden.openExternal('https://dash.cloudflare.com/profile/api-tokens')
            }}
          >
            Open Cloudflare API Tokens
          </a>{' '}
          · Missing permissions only disable the features that need them.
        </p>
        <div className="row">
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            placeholder={st.connected ? 'Paste a new token to replace the saved one' : 'Paste API token'}
            value={tokenDraft}
            onChange={(e) => setTokenDraft(e.target.value)}
            aria-label="Cloudflare API token"
          />
          <button onClick={connect} disabled={busy || !tokenDraft.trim()}>
            {st.connected ? 'Replace' : 'Connect'}
          </button>
          {st.connected && (
            <button className="ghost" onClick={disconnect} disabled={busy}>
              Disconnect
            </button>
          )}
        </div>
      </section>

      {st.connected && (
        <section className="card">
          <div className="row">
            <h3>2. Monitoring agent</h3>
            <span className={`pill ${st.workerUrl ? 'ok' : ''}`}>{st.workerUrl ? 'Deployed' : 'Not deployed'}</span>
          </div>
          <p className="small muted">
            Deploys a Worker named <code>sitewarden-agent</code> and a D1 database to your account. Every 30 minutes it checks uptime, watches your
            homepage for new third-party scripts and (with your keys) checks Safe Browsing and URLhaus. It also collects reports from the optional
            guard script and CSP. Free plan limits apply (100,000 Worker requests a day).
          </p>
          {st.workerUrl && (
            <p className="small">
              <code>{st.workerUrl}</code> · deployed {new Date(st.deployedAt!).toLocaleString()} · covering {st.deployedSites.join(', ') || 'no sites'}
            </p>
          )}
          <div className="form">
            <label>
              Account
              <select value={accountId} onChange={(e) => setAccountId(e.target.value)}>
                {st.accounts.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Alert webhook (optional{st.alertWebhookSet ? ', one is saved' : ''})
              <input
                type="password"
                value={webhook}
                onChange={(e) => setWebhook(e.target.value)}
                placeholder="Slack or Discord incoming webhook URL"
                autoComplete="off"
              />
            </label>
            <label className="check">
              <input type="checkbox" checked={copyKeys} onChange={(e) => setCopyKeys(e.target.checked)} />
              Copy my Safe Browsing and URLhaus keys into the Worker (stored as encrypted Worker secrets in my account)
            </label>
          </div>
          <div className="row">
            <button onClick={deploy} disabled={busy || !accountId}>
              {busy ? 'Working…' : st.workerUrl ? 'Redeploy / update' : 'Deploy agent'}
            </button>
            {st.workerUrl && (
              <button className="ghost" onClick={remove} disabled={busy}>
                Remove agent
              </button>
            )}
          </div>
          <p className="small muted">Redeploy after you add or verify a domain so the agent covers it.</p>
          {result && (
            <ul className="steps small">
              {result.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          )}
        </section>
      )}

      {st.connected && (
        <section className="card">
          <h3>3. Harden each site</h3>
          <p className="small muted">Open a domain in the sidebar and use its Protection tab to review and apply Cloudflare settings. Every change can be reverted.</p>
        </section>
      )}
    </div>
  )
}
