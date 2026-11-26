import { useEffect, useState } from 'react'
import type { DeepOptions, Domain, ScanProgress, ScanResult, Severity, ToolsStatus } from '../../../shared/types'
import { copy, errMsg } from '../util'
import FindingCard from './FindingCard'
import ProtectionPanel from './ProtectionPanel'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

interface Props {
  domain: Domain
  onChanged: () => Promise<void>
  onRemoved: () => Promise<void>
  onOpenCloudflare: () => void
  onOpenScanners: () => void
  onOpenOracle: () => void
}

export default function DomainView({ domain, onChanged, onRemoved, onOpenCloudflare, onOpenScanners, onOpenOracle }: Props): React.JSX.Element {
  const [scans, setScans] = useState<ScanResult[]>([])
  const [selected, setSelected] = useState<ScanResult | null>(null)
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [error, setError] = useState('')
  const [tab, setTab] = useState<'scan' | 'protection'>('scan')
  const [tools, setTools] = useState<ToolsStatus | null>(null)
  const [deep, setDeep] = useState<DeepOptions>({ nuclei: false, zap: false })
  const [cancelling, setCancelling] = useState(false)
  const [vmReady, setVmReady] = useState(false)

  useEffect(() => {
    const loadScans = (): Promise<void> =>
      window.sitewarden.listScans(domain.id).then((s) => {
        setScans(s)
        setSelected(s[0] ?? null)
      })
    void loadScans()
    // Pull any results the Oracle VM uploaded since last time.
    void window.sitewarden
      .vmImport()
      .then((n) => (n ? loadScans() : undefined))
      .catch(() => undefined)
    void window.sitewarden
      .vmStatus()
      .then((v) => setVmReady(v.available && v.tokenCreated && !v.needsRedeploy && Boolean(v.heartbeat) && v.sites.includes(domain.host)))
      .catch(() => undefined)
    void window.sitewarden.toolsStatus().then(setTools)
    return window.sitewarden.onScanProgress((p) => {
      if (p.domainId === domain.id) setProgress(p)
    })
  }, [domain.id])

  async function verify(): Promise<void> {
    setBusy(true)
    setError('')
    setMsg('')
    try {
      const r = await window.sitewarden.verifyDomain(domain.id)
      if (r.ok) setMsg(r.message)
      else setError(r.message)
      await onChanged()
    } catch (e) {
      setError(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  async function scan(): Promise<void> {
    setBusy(true)
    setError('')
    setMsg('')
    try {
      const r = await window.sitewarden.runScan(domain.id, deep)
      setScans((s) => [r, ...s])
      setSelected(r)
    } catch (e) {
      setError(errMsg(e))
      await onChanged()
    } finally {
      setBusy(false)
      setProgress(null)
      setCancelling(false)
    }
  }

  async function cancel(): Promise<void> {
    setCancelling(true)
    await window.sitewarden.cancelScan(domain.id)
  }

  async function remove(): Promise<void> {
    if (!confirm(`Remove ${domain.host} and its scan history from SiteWarden?`)) return
    await window.sitewarden.removeDomain(domain.id)
    await onRemoved()
  }

  async function exportReport(): Promise<void> {
    if (!selected) return
    const path = await window.sitewarden.exportReport(selected.id)
    if (path) setMsg(`Report saved to ${path}`)
  }

  const txtValue = `sitewarden-verification=${domain.verificationToken}`
  const metaTag = `<meta name="sitewarden-verification" content="${domain.verificationToken}">`

  return (
    <div className="page">
      <div className="row head">
        <div>
          <h1>{domain.host}</h1>
          <div className="muted small">
            {domain.verified
              ? `Ownership verified via ${domain.verifiedBy === 'dns' ? 'DNS' : 'meta tag'} on ${new Date(domain.verifiedAt!).toLocaleDateString()}`
              : 'Ownership not verified'}
          </div>
        </div>
        <div className="row">
          {domain.verified && !(busy && progress) && (
            <button onClick={scan} disabled={busy}>
              {deep.nuclei || deep.zap ? 'Run deep scan' : 'Run scan'}
            </button>
          )}
          {domain.verified && vmReady && !(busy && progress) && (
            <button
              className="ghost"
              disabled={busy}
              onClick={async () => {
                setError('')
                try {
                  const r = await window.sitewarden.vmScanNow(domain.id)
                  setMsg(r.alreadyQueued ? 'A scan on the Oracle agent is already queued.' : 'Queued on the Oracle agent. It starts within 10 minutes; results appear here when it finishes.')
                } catch (e) {
                  setError(errMsg(e))
                }
              }}
            >
              Scan on Oracle VM
            </button>
          )}
          {busy && progress && (
            <button className="ghost" onClick={cancel} disabled={cancelling}>
              {cancelling ? 'Cancelling…' : 'Cancel scan'}
            </button>
          )}
          <button className="ghost" onClick={remove} disabled={busy}>
            Remove
          </button>
        </div>
      </div>

      {error && <div className="error">{error}</div>}
      {msg && <div className="notice">{msg}</div>}

      <div className="tabs big" role="tablist">
        <button role="tab" aria-selected={tab === 'scan'} className={tab === 'scan' ? 'active' : ''} onClick={() => setTab('scan')}>
          Scan
        </button>
        <button role="tab" aria-selected={tab === 'protection'} className={tab === 'protection' ? 'active' : ''} onClick={() => setTab('protection')}>
          Protection
        </button>
      </div>

      {tab === 'protection' && <ProtectionPanel domain={domain} onOpenCloudflare={onOpenCloudflare} />}

      {tab === 'scan' && (
      <>

      {!domain.verified && (
        <section className="card">
          <h3>Prove you own this domain</h3>
          <p className="muted">
            SiteWarden only scans sites you control. Add <b>one</b> of these, then click Verify.
          </p>
          <h4>Option A: DNS TXT record (recommended)</h4>
          <p className="small muted">
            At your DNS provider, add a TXT record on <code>{domain.host}</code> (or on <code>_sitewarden.{domain.host}</code>) with this value:
          </p>
          <div className="copyline">
            <code>{txtValue}</code>
            <button className="ghost small" onClick={() => copy(txtValue)}>
              Copy
            </button>
          </div>
          <h4>Option B: meta tag</h4>
          <p className="small muted">
            Paste this inside the <code>&lt;head&gt;</code> of your homepage at https://{domain.host}/:
          </p>
          <div className="copyline">
            <code>{metaTag}</code>
            <button className="ghost small" onClick={() => copy(metaTag)}>
              Copy
            </button>
          </div>
          <button onClick={verify} disabled={busy}>
            {busy ? 'Checking…' : 'Verify'}
          </button>
        </section>
      )}

      {domain.verified && tools && !(busy && progress) && (
        <div className="deep row small">
          <span className="muted">Deep scan:</span>
          <label className="check">
            <input
              type="checkbox"
              disabled={!tools.nuclei.installed || busy}
              checked={deep.nuclei && tools.nuclei.installed}
              onChange={(e) => setDeep({ ...deep, nuclei: e.target.checked })}
            />
            Nuclei {!tools.nuclei.installed && <span className="muted">(not installed)</span>}
          </label>
          <label className="check">
            <input
              type="checkbox"
              disabled={!tools.zap.found || !tools.java.ok || busy}
              checked={deep.zap && tools.zap.found && tools.java.ok}
              onChange={(e) => setDeep({ ...deep, zap: e.target.checked })}
            />
            ZAP baseline {(!tools.zap.found || !tools.java.ok) && <span className="muted">({!tools.zap.found ? 'not found' : 'needs Java'})</span>}
          </label>
          {(!tools.nuclei.installed || !tools.zap.found || !tools.java.ok) && (
            <button className="ghost small" onClick={onOpenScanners}>
              Set up scanners
            </button>
          )}
          {(deep.nuclei || deep.zap) && <span className="muted">Takes several minutes and sends many requests to your site.</span>}
        </div>
      )}

      {busy && progress && (
        <div className="progress">
          <div className="bar" style={{ width: `${(progress.done / progress.total) * 100}%` }} />
          <span className="small">
            {progress.checkName} ({progress.done}/{progress.total}){progress.note ? ` · ${progress.note}` : ''}
          </span>
        </div>
      )}

      {selected && (
        <>
          <section className="summary card">
            <div className={`grade g-${selected.grade}`}>{selected.grade}</div>
            <div>
              <div className="score">{selected.score}/100</div>
              <div className="muted small">
                Scanned {new Date(selected.startedAt).toLocaleString()}
                {selected.origin === 'oracle' && (
                  <>
                    {' '}
                    · <span className="pill">Oracle VM deep scan</span>{' '}
                    <a href="#" onClick={(e) => (e.preventDefault(), onOpenOracle())}>
                      agent
                    </a>
                  </>
                )}
              </div>
              <div className="counts">
                {SEVERITIES.map((s) => {
                  const n = selected.findings.filter((f) => f.severity === s).length
                  return n ? (
                    <span key={s} className={`pill sev-${s}`}>
                      {n} {s}
                    </span>
                  ) : null
                })}
              </div>
            </div>
            <div className="spacer" />
            <div className="col">
              <button className="ghost" onClick={exportReport}>
                Export report
              </button>
              {scans.length > 1 && (
                <select
                  value={selected.id}
                  onChange={(e) => setSelected(scans.find((s) => s.id === e.target.value) ?? null)}
                  aria-label="Scan history"
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {new Date(s.startedAt).toLocaleString()} ({s.grade}){s.origin === 'oracle' ? ' · Oracle VM' : ''}
                    </option>
                  ))}
                </select>
              )}
            </div>
          </section>

          <h2>Findings</h2>
          {selected.findings.length === 0 && <p className="muted">No issues found by these checks.</p>}
          {selected.findings.map((f, i) => (
            <FindingCard key={`${selected.id}-${i}`} finding={f} />
          ))}

          <h2>Checks</h2>
          <table className="checks">
            <tbody>
              {selected.checks.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>
                    <span className={`pill st-${c.status}`}>{c.status}</span>
                  </td>
                  <td className="muted small">{c.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">
            These checks look at your site from the outside. They don't inspect files on your server, so they can miss malware that isn't visible
            in pages yet.
          </p>
        </>
      )}

      {domain.verified && !selected && !busy && <p className="muted">No scans yet. Click Run scan.</p>}
      </>
      )}
    </div>
  )
}
