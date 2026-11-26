import { useState } from 'react'
import type { Finding, Fix } from '../../../shared/types'
import { copy } from '../util'

export default function FindingCard({ finding }: { finding: Finding }): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const [fix, setFix] = useState<Fix | null>(null)
  const [tab, setTab] = useState(0)

  async function toggle(): Promise<void> {
    if (!open && finding.fixId && !fix) setFix(await window.sitewarden.getFix(finding.fixId))
    setOpen(!open)
  }

  const step = fix?.steps[tab]

  return (
    <section className={`finding sev-border-${finding.severity}`}>
      <button className="finding-head" onClick={toggle} aria-expanded={open}>
        <span className={`pill sev-${finding.severity}`}>{finding.severity}</span>
        <span className="title">{finding.title}</span>
        {finding.source && <span className="pill">{finding.source}</span>}
        <span className="chev">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="finding-body">
          <p>{finding.detail}</p>
          {finding.evidence && <pre className="evidence">{finding.evidence}</pre>}
          {!fix && (finding.remediation || finding.references?.length) && (
            <div className="fix">
              <h4>How to fix</h4>
              {finding.remediation && <p style={{ whiteSpace: 'pre-wrap' }}>{finding.remediation}</p>}
              {finding.references?.map((r) => (
                <div key={r} className="small">
                  <a
                    href={r}
                    onClick={(e) => {
                      e.preventDefault()
                      void window.sitewarden.openExternal(r)
                    }}
                  >
                    {r}
                  </a>
                </div>
              ))}
            </div>
          )}
          {fix && (
            <div className="fix">
              <h4>How to fix: {fix.title}</h4>
              <p className="muted small">{fix.why}</p>
              <div className="tabs" role="tablist">
                {fix.steps.map((s, i) => (
                  <button key={s.platform} role="tab" aria-selected={i === tab} className={i === tab ? 'active' : ''} onClick={() => setTab(i)}>
                    {s.platform}
                  </button>
                ))}
              </div>
              {step?.text && <p>{step.text}</p>}
              {step?.code && (
                <div className="code">
                  <pre>{step.code}</pre>
                  <button className="ghost small" onClick={() => copy(step.code!)}>
                    Copy
                  </button>
                </div>
              )}
              {fix.references?.map((r) => (
                <div key={r} className="small">
                  <a
                    href={r}
                    onClick={(e) => {
                      e.preventDefault()
                      void window.sitewarden.openExternal(r)
                    }}
                  >
                    {r}
                  </a>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  )
}
