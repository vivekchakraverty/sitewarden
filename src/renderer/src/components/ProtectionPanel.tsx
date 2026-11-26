import { useCallback, useEffect, useState } from 'react'
import type { AgentSummary, ApplyResult, CfChange, CfStatus, Domain, ZoneHardening } from '../../../shared/types'
import { copy, errMsg } from '../util'
import CspHelper from './CspHelper'

interface Props {
  domain: Domain
  onOpenCloudflare: () => void
}

export default function ProtectionPanel({ domain, onOpenCloudflare }: Props): React.JSX.Element {
  const [st, setSt] = useState<CfStatus | null>(null)
  const [hard, setHard] = useState<ZoneHardening | null>(null)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [results, setResults] = useState<ApplyResult[]>([])
  const [changes, setChanges] = useState<CfChange[]>([])
  const [summary, setSummary] = useState<AgentSummary | null>(null)
  const [summaryError, setSummaryError] = useState('')
  const [snippet, setSnippet] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const loadHardening = useCallback(async () => {
    const h = await window.sitewarden.cfHardening(domain.id)
    setHard(h)
    setPicked(new Set(h.items.filter((i) => i.available && !i.done && i.recommendedByDefault).map((i) => i.id)))
    setChanges(await window.sitewarden.cfChanges(domain.id))
  }, [domain.id])

  const loadAgent = useCallback(async () => {
    setSnippet(await window.sitewarden.guardSnippet(domain.id))
    try {
      setSummary(await window.sitewarden.agentSummary(domain.id))
      setSummaryError('')
    } catch (e) {
      setSummary(null)
      setSummaryError(errMsg(e))
    }
  }, [domain.id])

  useEffect(() => {
    void (async () => {
      const s = await window.sitewarden.cfStatus()
      setSt(s)
      if (s.connected && domain.verified) await loadHardening()
      if (s.workerUrl) await loadAgent()
    })()
  }, [domain.id, domain.verified, loadHardening, loadAgent])

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

  const apply = (): Promise<void> =>
    run(async () => {
      const risky = hard?.items.filter((i) => picked.has(i.id) && i.warning) ?? []
      if (risky.length && !confirm(`Apply ${picked.size} change(s) to ${hard?.zoneName}?\n\n${risky.map((i) => `${i.label}: ${i.warning}`).join('\n\n')}`)) return
      setResults(await window.sitewarden.cfApply(domain.id, [...picked]))
      await loadHardening()
    })

  const revert = (c: CfChange): Promise<void> =>
    run(async () => {
      if (!confirm(`Revert "${c.label}" to its previous value?`)) return
      setResults([await window.sitewarden.cfRevert(c.id)])
      await loadHardening()
    })

  if (!domain.verified) return <p className="muted">Verify ownership on the Scan tab first.</p>
  if (!st) return <p className="muted">Loading…</p>
  if (!st.connected) {
    return (
      <section className="card">
        <h3>Connect Cloudflare</h3>
        <p className="muted">
          DDoS protection, a firewall and bot blocking come from putting the site behind Cloudflare (free plan). Connect your account to harden its
          settings and turn on 24/7 monitoring.
        </p>
        <button onClick={onOpenCloudflare}>Set up Cloudflare</button>
      </section>
    )
  }

  const lastCheck = summary?.checks[0]
  const uptime = summary?.checks.length ? Math.round((summary.checks.filter((c) => c.ok).length / summary.checks.length) * 1000) / 10 : null
  const openAlerts = summary?.alerts.filter((a) => !a.acked) ?? []
  const unapproved = summary?.origins.filter((o) => !o.approved) ?? []

  return (
    <>
      {error && <div className="error">{error}</div>}

      <section className="card">
        <div className="row">
          <h3>Cloudflare settings{hard?.zoneName ? ` for ${hard.zoneName}` : ''}</h3>
          {hard?.plan && <span className="pill">{hard.plan}</span>}
        </div>
        {hard?.error && <div className="error small">{hard.error}</div>}
        {!hard && <p className="muted small">Reading zone settings…</p>}
        {hard && !hard.error && (
          <>
            <table className="checks harden">
              <tbody>
                {hard.items.map((i) => (
                  <tr key={i.id} className={i.available ? '' : 'disabled'}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={i.label}
                        disabled={!i.available || busy}
                        checked={picked.has(i.id)}
                        onChange={(e) => {
                          const next = new Set(picked)
                          if (e.target.checked) next.add(i.id)
                          else next.delete(i.id)
                          setPicked(next)
                        }}
                      />
                    </td>
                    <td>
                      <b>{i.label}</b>
                      <div className="small muted">{i.description}</div>
                      {i.warning && <div className="small warn">⚠ {i.warning}</div>}
                      {i.note && <div className="small muted">{i.note}</div>}
                    </td>
                    <td className="small">
                      <span className={`pill ${i.done ? 'ok' : ''}`}>{i.done ? 'done' : i.current}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="row">
              <button onClick={apply} disabled={busy || picked.size === 0}>
                {busy ? 'Applying…' : `Apply ${picked.size} selected`}
              </button>
              <button className="ghost" onClick={() => run(loadHardening)} disabled={busy}>
                Refresh
              </button>
            </div>
          </>
        )}
        {results.length > 0 && (
          <ul className="steps small">
            {results.map((r) => (
              <li key={r.id} className={r.ok ? '' : 'bad'}>
                {hard?.items.find((i) => i.id === r.id)?.label ?? r.id}: {r.message}
              </li>
            ))}
          </ul>
        )}
        {changes.length > 0 && (
          <details>
            <summary className="small">Change history ({changes.length})</summary>
            <table className="checks small">
              <tbody>
                {changes.map((c) => (
                  <tr key={c.id}>
                    <td>{c.label}</td>
                    <td className="muted">{new Date(c.appliedAt).toLocaleString()}</td>
                    <td>
                      {c.revertedAt ? (
                        <span className="muted">reverted</span>
                      ) : (
                        <button className="ghost small" onClick={() => revert(c)} disabled={busy}>
                          Revert
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        )}
      </section>

      <section className="card">
        <div className="row">
          <h3>24/7 monitoring</h3>
          {st.workerUrl && (
            <button className="ghost small" onClick={() => run(loadAgent)} disabled={busy}>
              Refresh
            </button>
          )}
        </div>
        {!st.workerUrl && (
          <>
            <p className="muted small">Deploy the monitoring agent to your Cloudflare account to get uptime, blacklist and script-injection alerts.</p>
            <button onClick={onOpenCloudflare}>Deploy agent</button>
          </>
        )}
        {st.workerUrl && summaryError && (
          <div className="notice-warn small">
            {summaryError}{' '}
            {/Redeploy/.test(summaryError) && (
              <button className="ghost small" onClick={onOpenCloudflare}>
                Open Cloudflare page
              </button>
            )}
          </div>
        )}
        {summary && (
          <>
            <div className="stats">
              <div>
                <div className="stat">{uptime === null ? '–' : `${uptime}%`}</div>
                <div className="small muted">uptime (last {summary.checks.length} checks)</div>
              </div>
              <div>
                <div className="stat">{lastCheck ? `${lastCheck.ms} ms` : '–'}</div>
                <div className="small muted">
                  {lastCheck ? `last check ${new Date(lastCheck.ts).toLocaleTimeString()} · ${lastCheck.ok ? `HTTP ${lastCheck.status}` : lastCheck.error || `HTTP ${lastCheck.status}`}` : 'first check within 30 min'}
                </div>
              </div>
              <div>
                <div className={`stat ${openAlerts.length ? 'sev-high' : ''}`}>{openAlerts.length}</div>
                <div className="small muted">open alerts</div>
              </div>
            </div>

            {summary.alerts.length > 0 && (
              <>
                <div className="row">
                  <h4 className="spacer">Alerts</h4>
                  {openAlerts.length > 0 && (
                    <button
                      className="ghost small"
                      disabled={busy}
                      onClick={() =>
                        run(async () => {
                          await window.sitewarden.agentAckAlerts(domain.id)
                          await loadAgent()
                        })
                      }
                    >
                      Mark all read
                    </button>
                  )}
                </div>
                <table className="checks small">
                  <tbody>
                    {summary.alerts.slice(0, 15).map((a) => (
                      <tr key={a.id} className={a.acked ? 'muted' : ''}>
                        <td>{new Date(a.ts).toLocaleString()}</td>
                        <td>
                          <span className="pill">{a.kind.replace('_', ' ')}</span>
                        </td>
                        <td>{a.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            <h4>Third-party scripts ({summary.origins.length})</h4>
            <p className="small muted">
              Scripts seen in your homepage HTML or in visitors' browsers. Approve the ones you expect; an unexpected new script can mean the site was
              injected with a card skimmer or malware.
            </p>
            {summary.origins.length === 0 && <p className="small muted">None seen yet.</p>}
            <table className="checks small">
              <tbody>
                {[...unapproved, ...summary.origins.filter((o) => o.approved)].slice(0, 40).map((o) => (
                  <tr key={o.origin}>
                    <td className="mono">{o.origin}</td>
                    <td className="muted">
                      {o.source} · first {new Date(o.firstSeen).toLocaleDateString()}
                    </td>
                    <td>
                      <button
                        className={o.approved ? 'ghost small' : 'small'}
                        disabled={busy}
                        onClick={() =>
                          run(async () => {
                            await window.sitewarden.agentApprove(domain.id, o.origin, !o.approved)
                            await loadAgent()
                          })
                        }
                      >
                        {o.approved ? 'Unapprove' : 'Approve'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {summary.csp.length > 0 && (
              <>
                <h4>CSP reports</h4>
                <table className="checks small">
                  <tbody>
                    {summary.csp.slice(0, 20).map((r) => (
                      <tr key={`${r.directive}|${r.blocked}`}>
                        <td>{r.directive}</td>
                        <td className="mono">{r.blocked || '(inline)'}</td>
                        <td>{r.count}×</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </>
        )}
        {snippet && (
          <>
            <h4>Optional: browser guard</h4>
            <p className="small muted">
              Add this to every page's &lt;head&gt; to also watch scripts that only appear in visitors' browsers (injected by tag managers, plugins or
              attackers). It samples 10% of page views and sends script URLs without query strings, nothing else.
            </p>
            <div className="copyline">
              <code>{snippet}</code>
              <button className="ghost small" onClick={() => copy(snippet)}>
                Copy
              </button>
            </div>
            <CspHelper domainId={domain.id} snippet={snippet} onChanged={() => void loadHardening()} />
          </>
        )}
      </section>
    </>
  )
}
