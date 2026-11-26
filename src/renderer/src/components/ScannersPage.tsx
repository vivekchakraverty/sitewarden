import { useEffect, useState } from 'react'
import type { ScannerSettings, ToolProgress, ToolsStatus } from '../../../shared/types'
import { errMsg } from '../util'

function ext(url: string): void {
  void window.sitewarden.openExternal(url)
}

export default function ScannersPage(): React.JSX.Element {
  const [st, setSt] = useState<ToolsStatus | null>(null)
  const [draft, setDraft] = useState<ScannerSettings | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [progress, setProgress] = useState<ToolProgress | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    void window.sitewarden.toolsStatus().then((s) => {
      setSt(s)
      setDraft(s.settings)
    })
    const off1 = window.sitewarden.onToolProgress(setProgress)
    const off2 = window.sitewarden.onAutoSetup((a) => {
      setBusy(a.running ? 'auto' : null)
      if (!a.running) void window.sitewarden.toolsStatus().then(setSt)
    })
    void window.sitewarden.autoSetupState().then((a) => a.running && setBusy('auto'))
    return () => {
      off1()
      off2()
    }
  }, [])

  async function run(label: string, fn: () => Promise<ToolsStatus>, confirmText?: string): Promise<void> {
    if (confirmText && !confirm(confirmText)) return
    setBusy(label)
    setError('')
    setMsg('')
    setProgress(null)
    try {
      const s = await fn()
      setSt(s)
      setDraft(s.settings)
    } catch (e) {
      setError(errMsg(e))
    } finally {
      setBusy(null)
    }
  }

  if (!st || !draft) return <div className="page muted">Checking installed scanners…</div>

  const bar = (tools: ToolProgress['tool'][]): React.JSX.Element | null =>
    busy && progress && tools.includes(progress.tool) ? (
      <div className="progress">
        <div className="bar" style={{ width: `${progress.pct ?? 0}%` }} />
        <span className="small">
          {progress.message}
          {progress.pct !== undefined && progress.pct < 100 ? ` · ${progress.pct}%` : ''}
        </span>
      </div>
    ) : null

  const num = (k: keyof ScannerSettings, label: string, min: number, max: number, unit: string): React.JSX.Element => (
    <label>
      {label}
      <span className="row">
        <input
          type="number"
          min={min}
          max={max}
          value={draft[k] as number}
          onChange={(e) => setDraft({ ...draft, [k]: Number(e.target.value) })}
          style={{ maxWidth: 110 }}
        />
        <span className="small muted">{unit}</span>
      </span>
    </label>
  )

  return (
    <div className="page">
      <h1>Deep scanners</h1>
      <p className="muted">
        Optional open-source scanners that run on this computer for a deeper look than the quick checks. They send many requests to your site
        (minutes, not seconds), so only use them on sites you own, and expect your host or Cloudflare to notice. Both only run against verified
        domains.
      </p>
      {error && <div className="error">{error}</div>}
      {msg && <div className="notice">{msg}</div>}

      <section className="card">
        <div className="row">
          <h3>Nuclei</h3>
          <span className={`pill ${st.nuclei.installed ? 'ok' : ''}`}>{st.nuclei.installed ? `v${st.nuclei.version}` : 'Not installed'}</span>
        </div>
        <p className="small muted">
          ProjectDiscovery's template scanner: thousands of community checks for known CVEs, misconfigurations, exposed panels and files. SiteWarden
          skips intrusive, denial-of-service, fuzzing and brute-force templates.{' '}
          <a href="https://github.com/projectdiscovery/nuclei" onClick={(e) => (e.preventDefault(), ext('https://github.com/projectdiscovery/nuclei'))}>
            Project page
          </a>
        </p>
        {st.nuclei.installed && (
          <p className="small">
            Templates: {st.nuclei.templateCount ? `${st.nuclei.templateCount.toLocaleString()} ` : 'none '}
            {st.nuclei.templatesUpdatedAt ? `· updated ${new Date(st.nuclei.templatesUpdatedAt).toLocaleDateString()}` : ''}
          </p>
        )}
        {bar(['nuclei', 'templates'])}
        <div className="row">
          {!st.nuclei.installed ? (
            <button
              disabled={Boolean(busy)}
              onClick={() =>
                run(
                  'nuclei',
                  () => window.sitewarden.installNuclei(),
                  'Download Nuclei from its official GitHub release (about 40 MB, checksum-verified), then its templates (about 100 MB of small files from GitHub)?'
                )
              }
            >
              {busy === 'nuclei' ? 'Installing…' : 'Install Nuclei'}
            </button>
          ) : (
            <>
              <button disabled={Boolean(busy)} onClick={() => run('templates', () => window.sitewarden.updateTemplates())}>
                {busy === 'templates' ? 'Updating…' : 'Update templates'}
              </button>
              <button className="ghost" disabled={Boolean(busy)} onClick={() => run('nuclei', () => window.sitewarden.installNuclei(), 'Download and install the latest Nuclei release?')}>
                Update Nuclei
              </button>
              <button className="ghost" disabled={Boolean(busy)} onClick={() => run('rm-nuclei', () => window.sitewarden.removeTool('nuclei'), 'Remove Nuclei and its templates from this computer?')}>
                Remove
              </button>
            </>
          )}
        </div>
      </section>

      <section className="card">
        <div className="row">
          <h3>OWASP ZAP</h3>
          <span className={`pill ${st.zap.found && st.java.ok ? 'ok' : ''}`}>
            {st.zap.found ? (st.java.ok ? `v${st.zap.version} ready` : `v${st.zap.version} · needs Java`) : 'Not found'}
          </span>
        </div>
        <p className="small muted">
          The baseline scan crawls your site for a few minutes and reports issues ZAP's passive rules spot in the responses (information leaks, unsafe
          forms, CORS, cache and cookie problems). It sends no attacks.
        </p>
        {st.zap.found ? (
          <p className="small">
            <code>{st.zap.dir}</code>
            {st.zap.custom && (
              <button className="ghost small" style={{ marginLeft: 8 }} disabled={Boolean(busy)} onClick={() => run('zapdir', () => window.sitewarden.resetZapDir())}>
                Use auto-detect
              </button>
            )}
          </p>
        ) : (
          <p className="small">
            Install ZAP from{' '}
            <a href="https://www.zaproxy.org/download/" onClick={(e) => (e.preventDefault(), ext('https://www.zaproxy.org/download/'))}>
              zaproxy.org/download
            </a>{' '}
            (free), then come back here. If you installed it somewhere unusual, choose its folder.
          </p>
        )}
        <div className="row">
          <button className="ghost" disabled={Boolean(busy)} onClick={() => run('zapdir', () => window.sitewarden.chooseZapDir())}>
            Choose ZAP folder…
          </button>
        </div>

        <h4>Java runtime</h4>
        {st.java.ok ? (
          <p className="small">
            <span className="pill ok">Java {st.java.version}</span> <code>{st.java.path}</code>
            {st.java.managed && ' (installed by SiteWarden)'}
          </p>
        ) : (
          <p className="small">
            <span className="pill sev-medium">missing</span> {st.java.note} SiteWarden can install a private copy of Eclipse Temurin 21 just for ZAP. It
            doesn't change your system Java.
          </p>
        )}
        {bar(['java'])}
        <div className="row">
          {!st.java.ok && (
            <button
              disabled={Boolean(busy)}
              onClick={() =>
                run('java', () => window.sitewarden.installJava(), 'Download the Eclipse Temurin 21 Java runtime from adoptium.net (about 45 MB, checksum-verified) into SiteWarden\'s own folder?')
              }
            >
              {busy === 'java' ? 'Installing…' : 'Install Java runtime'}
            </button>
          )}
          {st.java.managed && (
            <button className="ghost" disabled={Boolean(busy)} onClick={() => run('rm-java', () => window.sitewarden.removeTool('java'), "Remove SiteWarden's private Java runtime?")}>
              Remove Java runtime
            </button>
          )}
        </div>
      </section>

      <section className="card">
        <h3>Settings</h3>
        <p className="small muted">Lower these if your host is small or rate-limits you.</p>
        <div className="form grid2">
          {num('nucleiRate', 'Nuclei request rate', 1, 150, 'requests / second')}
          {num('nucleiMaxMinutes', 'Nuclei time limit', 2, 120, 'minutes')}
          {num('zapSpiderMinutes', 'ZAP crawl time', 1, 30, 'minutes')}
          {num('zapMaxMinutes', 'ZAP time limit', 3, 120, 'minutes')}
          <label className="check" style={{ gridColumn: '1 / -1' }}>
            <input type="checkbox" checked={draft.autoInstall} onChange={(e) => setDraft({ ...draft, autoInstall: e.target.checked })} />
            Set up scanners automatically: install Nuclei on first launch, refresh its templates weekly, and add the Java runtime when ZAP needs it
          </label>
          <label className="check" style={{ gridColumn: '1 / -1' }}>
            <input type="checkbox" checked={draft.nucleiInteractsh} onChange={(e) => setDraft({ ...draft, nucleiInteractsh: e.target.checked })} />
            Allow Nuclei out-of-band checks (finds blind SSRF and similar, but sends probe data through ProjectDiscovery's public interactsh servers)
          </label>
        </div>
        <button
          disabled={Boolean(busy)}
          onClick={() =>
            run('settings', async () => {
              const s = await window.sitewarden.saveScannerSettings(draft)
              setMsg('Saved.')
              return s
            })
          }
        >
          Save settings
        </button>
      </section>
    </div>
  )
}
