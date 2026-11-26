import { useCallback, useEffect, useState } from 'react'
import type { Domain } from '../../shared/types'
import DomainView from './components/DomainView'
import CloudflarePage from './components/CloudflarePage'
import OraclePage from './components/OraclePage'
import ScannersPage from './components/ScannersPage'
import SetupBanner from './components/SetupBanner'
import Settings from './components/Settings'
import { errMsg } from './util'

type View = { kind: 'domain'; id: string } | { kind: 'settings' } | { kind: 'cloudflare' } | { kind: 'scanners' } | { kind: 'oracle' } | { kind: 'welcome' }

export default function App(): React.JSX.Element {
  const [domains, setDomains] = useState<Domain[]>([])
  const [view, setView] = useState<View>({ kind: 'welcome' })
  const [input, setInput] = useState('')
  const [error, setError] = useState('')

  const refresh = useCallback(async () => setDomains(await window.sitewarden.listDomains()), [])
  useEffect(() => {
    void refresh()
  }, [refresh])

  async function add(e: React.FormEvent): Promise<void> {
    e.preventDefault()
    setError('')
    try {
      const d = await window.sitewarden.addDomain(input)
      setInput('')
      await refresh()
      setView({ kind: 'domain', id: d.id })
    } catch (err) {
      setError(errMsg(err))
    }
  }

  const current = view.kind === 'domain' ? domains.find((d) => d.id === view.id) : undefined

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="logo" aria-hidden>
            ◆
          </span>{' '}
          SiteWarden
        </div>
        <form onSubmit={add} className="add">
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="example.com" aria-label="Domain to add" />
          <button type="submit" disabled={!input.trim()}>
            Add
          </button>
        </form>
        {error && <div className="error small">{error}</div>}
        <nav className="domains">
          {domains.map((d) => (
            <button
              key={d.id}
              className={`domain ${current?.id === d.id ? 'active' : ''}`}
              onClick={() => setView({ kind: 'domain', id: d.id })}
            >
              <span className={`dot ${d.verified ? 'ok' : 'pending'}`} title={d.verified ? 'Verified' : 'Not verified'} />
              {d.host}
            </button>
          ))}
          {!domains.length && <p className="muted small">Add a website you own to get started.</p>}
        </nav>
        <button className={`settings-btn ${view.kind === 'cloudflare' ? 'active' : ''}`} onClick={() => setView({ kind: 'cloudflare' })}>
          Cloudflare
        </button>
        <button className={`settings-btn ${view.kind === 'scanners' ? 'active' : ''}`} onClick={() => setView({ kind: 'scanners' })}>
          Deep scanners
        </button>
        <button className={`settings-btn ${view.kind === 'oracle' ? 'active' : ''}`} onClick={() => setView({ kind: 'oracle' })}>
          Oracle agent
        </button>
        <button className={`settings-btn ${view.kind === 'settings' ? 'active' : ''}`} onClick={() => setView({ kind: 'settings' })}>
          API keys
        </button>
      </aside>
      <main className="content">
        <SetupBanner onOpenScanners={() => setView({ kind: 'scanners' })} />
        {view.kind === 'settings' && <Settings />}
        {view.kind === 'scanners' && <ScannersPage />}
        {view.kind === 'oracle' && <OraclePage onOpenCloudflare={() => setView({ kind: 'cloudflare' })} />}
        {view.kind === 'cloudflare' && <CloudflarePage onChanged={() => void refresh()} />}
        {current && (
          <DomainView
            key={current.id}
            domain={current}
            onChanged={refresh}
            onRemoved={async () => {
              await refresh()
              setView({ kind: 'welcome' })
            }}
            onOpenCloudflare={() => setView({ kind: 'cloudflare' })}
            onOpenScanners={() => setView({ kind: 'scanners' })}
            onOpenOracle={() => setView({ kind: 'oracle' })}
          />
        )}
        {view.kind === 'welcome' && (
          <div className="welcome">
            <h1>Check your website's security</h1>
            <ol>
              <li>Add a domain you own in the sidebar.</li>
              <li>Prove ownership with a DNS record or a meta tag.</li>
              <li>
                Add your free API keys under <b>API keys</b> for malware and blacklist checks (optional).
              </li>
              <li>Run a scan and follow the fix steps for each finding.</li>
            </ol>
            <p className="muted">Your keys are encrypted with your operating system's key store and never leave this computer except to call the service they belong to.</p>
          </div>
        )}
      </main>
    </div>
  )
}
