import { useEffect, useState } from 'react'
import type { AutoSetupState, ToolProgress } from '../../../shared/types'

/** Shows first-launch tool downloads on every page, with a Stop button. */
export default function SetupBanner({ onOpenScanners }: { onOpenScanners: () => void }): React.JSX.Element | null {
  const [state, setState] = useState<AutoSetupState | null>(null)
  const [progress, setProgress] = useState<ToolProgress | null>(null)
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    void window.sitewarden.autoSetupState().then(setState)
    const off1 = window.sitewarden.onAutoSetup((s) => {
      setState(s)
      setDismissed(false)
    })
    const off2 = window.sitewarden.onToolProgress(setProgress)
    return () => {
      off1()
      off2()
    }
  }, [])

  if (!state || dismissed) return null
  if (state.running) {
    return (
      <div className="setup-banner">
        <div className="grow">
          <b>{state.step ?? 'Setting up deep scanners'}…</b>
          <div className="small muted">
            {progress?.message ?? 'Starting'}
            {progress?.pct !== undefined && progress.pct < 100 ? ` · ${progress.pct}%` : ''} · one-time download, checksum-verified. You can keep using
            the app.
          </div>
          {progress?.pct !== undefined && (
            <div className="mini-bar">
              <div style={{ width: `${progress.pct}%` }} />
            </div>
          )}
        </div>
        <button className="ghost small" onClick={() => void window.sitewarden.stopAutoSetup()}>
          Stop
        </button>
      </div>
    )
  }
  if (state.error) {
    return (
      <div className="setup-banner warn-banner">
        <div className="grow small">
          <b>Deep scanner setup didn't finish.</b> {state.error}
        </div>
        <button className="ghost small" onClick={onOpenScanners}>
          Open Deep scanners
        </button>
        <button className="ghost small" onClick={() => setDismissed(true)} aria-label="Dismiss">
          ✕
        </button>
      </div>
    )
  }
  return null
}
