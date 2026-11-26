import { useEffect, useState } from 'react'
import type { VmSettings, VmStatus } from '../../../shared/types'
import { copy, errMsg } from '../util'

const ext = (url: string): void => void window.sitewarden.openExternal(url)

function ago(ts: string): string {
  const m = Math.round((Date.now() - new Date(ts).getTime()) / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m} min ago`
  const h = Math.round(m / 60)
  return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} days ago`
}

export default function OraclePage({ onOpenCloudflare }: { onOpenCloudflare: () => void }): React.JSX.Element {
  const [st, setSt] = useState<VmStatus | null>(null)
  const [draft, setDraft] = useState<VmSettings | null>(null)
  const [cloudInit, setCloudInit] = useState<string | null>(null)
  const [showInit, setShowInit] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [rotateCmd, setRotateCmd] = useState('')

  const load = async (): Promise<void> => {
    const s = await window.sitewarden.vmStatus()
    setSt(s)
    if (s.settings) setDraft(s.settings)
    if (s.tokenCreated && s.available && !s.needsRedeploy) {
      try {
        setCloudInit(await window.sitewarden.vmCloudInit())
      } catch {
        setCloudInit(null)
      }
    }
    const n = await window.sitewarden.vmImport().catch(() => 0)
    if (n) setMsg(`Imported ${n} new scan result(s) from the VM into your scan history.`)
  }
  useEffect(() => {
    void load()
  }, [])

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

  if (!st) return <div className="page muted">Loading…</div>

  const online = st.heartbeat && Date.now() - new Date(st.heartbeat.ts).getTime() < 30 * 60_000
  const steps: [string, React.JSX.Element][] = [
    [
      'Create a free Oracle Cloud account',
      <>
        Sign up at{' '}
        <a href="https://signup.cloud.oracle.com/" onClick={(e) => (e.preventDefault(), ext('https://signup.cloud.oracle.com/'))}>
          signup.cloud.oracle.com
        </a>
        . A card is needed for identity checks; Always Free resources are not charged.
      </>
    ],
    ['Create an instance', <>In the Oracle Cloud console: Compute › Instances › Create instance.</>],
    ['Image', <>Change image → Ubuntu → Canonical Ubuntu 24.04 (or 22.04).</>],
    [
      'Shape',
      <>
        Change shape → Ampere → VM.Standard.A1.Flex with 1 OCPU and 6 GB memory (Always Free eligible). If Oracle says there's no capacity, try another
        availability domain or try again later.
      </>
    ],
    ['Networking', <>Keep the defaults. The agent needs no open ports. You can also remove the SSH rule from the subnet's security list if you never log in.</>],
    ['SSH key', <>Let Oracle generate a key pair and download the private key (needed only if you want to log in later).</>],
    ['Paste the cloud-init', <>Show advanced options › Management › Initialization script › Paste cloud-init script, and paste the script below.</>],
    ['Create', <>Click Create. After about 5 minutes the VM checks in here. The first scan starts within 10 minutes and takes 15–30 minutes per site.</>]
  ]

  return (
    <div className="page">
      <h1>Oracle scan agent</h1>
      <p className="muted">
        Run the deep scanners (Nuclei + ZAP baseline) on a free Oracle Cloud VM on a schedule, so scans happen from a server even when this computer is
        off. The VM only makes outbound requests to your Cloudflare agent; results appear in each domain's scan history.
      </p>
      {error && <div className="error">{error}</div>}
      {msg && <div className="notice">{msg}</div>}

      {!st.available && (
        <section className="card">
          <h3>Cloudflare agent needed</h3>
          <p className="small muted">{st.reason}</p>
          <button onClick={onOpenCloudflare}>Open Cloudflare</button>
        </section>
      )}

      {st.available && (
        <section className="card">
          <div className="row">
            <h3>Status</h3>
            <span className={`pill ${online ? 'ok' : ''}`}>{!st.tokenCreated ? 'not set up' : !st.heartbeat ? 'waiting for VM' : online ? 'online' : 'offline'}</span>
            <button className="ghost small" onClick={() => run(load)} disabled={busy}>
              Refresh
            </button>
          </div>
          {st.reason && <div className="notice-warn small">{st.reason}</div>}
          {st.heartbeat && (
            <p className="small">
              Last check-in {ago(st.heartbeat.ts)} from <code>{st.heartbeat.hostname}</code> · agent {st.heartbeat.agentVersion}
              {st.heartbeat.diskFreeGb != null && ` · ${st.heartbeat.diskFreeGb} GB free`}
              {st.heartbeat.state === 'scanning' && st.heartbeat.site && <> · scanning <b>{st.heartbeat.site}</b></>}
            </p>
          )}
          {st.tokenCreated && !st.heartbeat && !st.needsRedeploy && (
            <p className="small muted">No check-in yet. Once you create the VM with the script below, it reports in after about 5 minutes.</p>
          )}
          {st.jobs.length > 0 && <p className="small">Queued: {st.jobs.map((j) => j.site).join(', ')}</p>}
          {st.latest.length > 0 && (
            <table className="checks small">
              <tbody>
                {st.latest.map((r) => (
                  <tr key={r.id}>
                    <td>{r.site}</td>
                    <td className="muted">last scan {ago(r.finishedAt)}</td>
                    <td>
                      {r.high > 0 ? <span className="pill sev-high">{r.high} high/critical</span> : <span className="pill ok">no high issues</span>}
                    </td>
                    <td className="muted">{r.errors.join('; ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {!st.tokenCreated || st.needsRedeploy ? (
            <button
              disabled={busy}
              onClick={() =>
                run(async () => {
                  setSt(await window.sitewarden.vmSetup())
                  await load()
                })
              }
            >
              {busy ? 'Setting up…' : st.tokenCreated ? 'Update the Cloudflare agent' : 'Set up the VM agent'}
            </button>
          ) : null}
          <p className="small muted">Scans cover the domains your Cloudflare agent covers: {st.sites.join(', ') || 'none'}.</p>
        </section>
      )}

      {st.available && st.tokenCreated && !st.needsRedeploy && cloudInit && (
        <section className="card">
          <h3>Create the VM</h3>
          <ol className="guide small">
            {steps.map(([title, body]) => (
              <li key={title}>
                <b>{title}.</b> {body}
              </li>
            ))}
          </ol>
          <div className="row">
            <button onClick={() => copy(cloudInit).then(() => setMsg('cloud-init copied. Paste it into the Oracle "Initialization script" box.'))}>Copy cloud-init</button>
            <button
              className="ghost"
              onClick={() =>
                run(async () => {
                  const p = await window.sitewarden.vmSaveCloudInit()
                  if (p) setMsg(`Saved to ${p}. It contains a secret token; delete it once the VM is running.`)
                })
              }
            >
              Save as file…
            </button>
            <button className="ghost" onClick={() => setShowInit(!showInit)}>
              {showInit ? 'Hide' : 'Show'} script
            </button>
          </div>
          <p className="small muted">The script contains the VM's secret token. It installs Docker, the official Nuclei and ZAP images, and a small Python agent run by a systemd timer.</p>
          {showInit && <pre className="evidence" style={{ maxHeight: 280, overflow: 'auto' }}>{cloudInit.replace(/(content: )([A-Za-z0-9+/=]{80,})/g, '$1<base64, hidden>')}</pre>}
          <p className="small muted">
            Any Linux server with Docker works too: save the script and run it with cloud-init, or use its steps by hand.
          </p>
        </section>
      )}

      {st.available && st.tokenCreated && !st.needsRedeploy && draft && (
        <section className="card">
          <h3>Schedule</h3>
          <div className="form grid2">
            <label className="check" style={{ gridColumn: '1 / -1' }}>
              <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
              Scan on a schedule ("Scan now" requests still run when this is off)
            </label>
            <label>
              Scan each site every
              <span className="row">
                <input type="number" min={1} max={720} value={draft.intervalHours} style={{ maxWidth: 110 }} onChange={(e) => setDraft({ ...draft, intervalHours: Number(e.target.value) })} />
                <span className="small muted">hours</span>
              </span>
            </label>
            <label>
              Nuclei request rate
              <span className="row">
                <input type="number" min={1} max={150} value={draft.nucleiRate} style={{ maxWidth: 110 }} onChange={(e) => setDraft({ ...draft, nucleiRate: Number(e.target.value) })} />
                <span className="small muted">requests / second</span>
              </span>
            </label>
            <label>
              Nuclei time limit
              <span className="row">
                <input type="number" min={2} max={180} value={draft.nucleiMaxMinutes} style={{ maxWidth: 110 }} onChange={(e) => setDraft({ ...draft, nucleiMaxMinutes: Number(e.target.value) })} />
                <span className="small muted">minutes</span>
              </span>
            </label>
            <label>
              ZAP crawl time
              <span className="row">
                <input type="number" min={1} max={30} value={draft.zapSpiderMinutes} style={{ maxWidth: 110 }} onChange={(e) => setDraft({ ...draft, zapSpiderMinutes: Number(e.target.value) })} />
                <span className="small muted">minutes</span>
              </span>
            </label>
            <label className="check" style={{ gridColumn: '1 / -1' }}>
              <input type="checkbox" checked={draft.nucleiInteractsh} onChange={(e) => setDraft({ ...draft, nucleiInteractsh: e.target.checked })} />
              Allow Nuclei out-of-band checks (sends probe data through ProjectDiscovery's interactsh servers)
            </label>
          </div>
          <div className="row">
            <button
              disabled={busy}
              onClick={() =>
                run(async () => {
                  const s = await window.sitewarden.vmSaveSettings(draft)
                  setSt(s)
                  if (s.settings) setDraft(s.settings)
                  setMsg('Saved. The VM picks it up on its next check-in.')
                })
              }
            >
              Save schedule
            </button>
          </div>
        </section>
      )}

      {st.available && st.tokenCreated && !st.needsRedeploy && (
        <section className="card">
          <h3>Security</h3>
          <p className="small muted">
            The VM token can only read the site list and schedule and upload results; it can't read your monitoring data or change anything. If the VM
            or the script leaks, rotate the token. The old one stops working right away.
          </p>
          <button
            className="ghost"
            disabled={busy}
            onClick={() =>
              run(async () => {
                if (!confirm('Create a new VM token? The running VM stops working until you update it (a command is shown next).')) return
                const r = await window.sitewarden.vmRotateToken()
                setSt(r.status)
                setRotateCmd(r.command)
                setCloudInit(await window.sitewarden.vmCloudInit())
              })
            }
          >
            Rotate VM token
          </button>
          {rotateCmd && (
            <>
              <p className="small">On the VM (SSH in as ubuntu), run:</p>
              <div className="copyline">
                <code>{rotateCmd}</code>
                <button className="ghost small" onClick={() => copy(rotateCmd)}>
                  Copy
                </button>
              </div>
              <p className="small muted">New VMs: the cloud-init above already contains the new token.</p>
            </>
          )}
        </section>
      )}
    </div>
  )
}
