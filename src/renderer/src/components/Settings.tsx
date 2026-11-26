import { useEffect, useState } from 'react'
import type { KeyInfo } from '../../../shared/types'
import { errMsg } from '../util'

export default function Settings(): React.JSX.Element {
  const [keys, setKeys] = useState<KeyInfo[]>([])
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [msg, setMsg] = useState<Record<string, string>>({})
  const [encOk, setEncOk] = useState(true)

  const load = async (): Promise<void> => {
    setKeys(await window.sitewarden.listKeys())
    setEncOk(await window.sitewarden.encryptionAvailable())
  }
  useEffect(() => {
    void load()
  }, [])

  async function save(k: KeyInfo): Promise<void> {
    try {
      await window.sitewarden.setKey(k.name, drafts[k.name] ?? '')
      setDrafts((d) => ({ ...d, [k.name]: '' }))
      setMsg((m) => ({ ...m, [k.name]: 'Saved.' }))
      await load()
    } catch (e) {
      setMsg((m) => ({ ...m, [k.name]: errMsg(e) }))
    }
  }

  async function clear(k: KeyInfo): Promise<void> {
    await window.sitewarden.clearKey(k.name)
    setMsg((m) => ({ ...m, [k.name]: 'Removed.' }))
    await load()
  }

  return (
    <div className="page">
      <h1>API keys</h1>
      <p className="muted">
        These free services power the malware and blacklist checks. Each key is encrypted with your operating system's key store and only sent to
        its own service. Checks without a key are skipped.
      </p>
      {!encOk && <div className="error">OS encryption is unavailable on this system, so keys cannot be stored safely.</div>}
      {keys.map((k) => (
        <section key={k.name} className="card">
          <div className="row">
            <h3>{k.label}</h3>
            <span className={`pill ${k.isSet ? 'ok' : ''}`}>{k.isSet ? 'Saved' : 'Not set'}</span>
          </div>
          <p className="muted small">
            {k.help}{' '}
            <a
              href={k.signupUrl}
              onClick={(e) => {
                e.preventDefault()
                void window.sitewarden.openExternal(k.signupUrl)
              }}
            >
              Get a key
            </a>
          </p>
          <div className="row">
            <input
              type="password"
              autoComplete="off"
              spellCheck={false}
              placeholder={k.isSet ? 'Paste a new key to replace the saved one' : 'Paste key'}
              value={drafts[k.name] ?? ''}
              onChange={(e) => setDrafts((d) => ({ ...d, [k.name]: e.target.value }))}
              aria-label={k.label}
            />
            <button onClick={() => save(k)} disabled={!drafts[k.name]?.trim() || !encOk}>
              Save
            </button>
            {k.isSet && (
              <button className="ghost" onClick={() => clear(k)}>
                Remove
              </button>
            )}
          </div>
          {msg[k.name] && <div className="small muted">{msg[k.name]}</div>}
        </section>
      ))}
    </div>
  )
}
