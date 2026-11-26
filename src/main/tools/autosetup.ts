// First-launch setup: after the app is installed, the first launch downloads the deep-scan tools in the
// background (with visible progress and a Stop button). Later launches only top things up:
//  - Nuclei templates older than 7 days are refreshed
//  - the private Java runtime is installed once ZAP is present but no Java 17+ is
// Failures are recorded and retried on the next launch. Turn it off with Settings > autoInstall.
import type { AutoSetupState, ToolProgress } from '../../shared/types'
import { store } from '../store'
import { findJava, installJava, installNuclei, nucleiPath, settings, templatesUpdatedAt, updateTemplates, withInstallLock, zapInfo } from './manager'

const TEMPLATE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

let state: AutoSetupState = { running: false, doneAt: store.get<string>('autoSetupDoneAt') }
let controller: AbortController | null = null

export const autoSetupState = (): AutoSetupState => state

export function stopAutoSetup(): void {
  controller?.abort()
}

interface Hooks {
  progress(p: ToolProgress): void
  state(s: AutoSetupState): void
}

export async function plannedSteps(): Promise<('nuclei' | 'templates' | 'java')[]> {
  const steps: ('nuclei' | 'templates' | 'java')[] = []
  if (!nucleiPath()) steps.push('nuclei') // includes templates
  else {
    const at = templatesUpdatedAt()
    if (!at || Date.now() - new Date(at).getTime() > TEMPLATE_MAX_AGE_MS) steps.push('templates')
  }
  if (zapInfo().found && !(await findJava())) steps.push('java')
  return steps
}

export async function runAutoSetup(hooks: Hooks): Promise<void> {
  if (state.running || !settings().autoInstall) return
  const steps = await plannedSteps()
  if (!steps.length) {
    if (!state.doneAt) {
      state = { running: false, doneAt: new Date().toISOString() }
      store.set('autoSetupDoneAt', state.doneAt)
    }
    return
  }
  controller = new AbortController()
  const set = (s: Partial<AutoSetupState>): void => {
    state = { ...state, ...s }
    hooks.state(state)
  }
  set({ running: true, error: undefined })
  const labels = { nuclei: 'Installing Nuclei and its templates', templates: 'Refreshing Nuclei templates', java: 'Installing the Java runtime for ZAP' }
  try {
    for (const step of steps) {
      if (controller.signal.aborted) break
      set({ step: labels[step] })
      console.log(`[auto-setup] ${labels[step]}`)
      await withInstallLock(labels[step], () => {
        const progress = (p: ToolProgress): void => hooks.progress(p)
        if (step === 'nuclei') return installNuclei(progress, controller!.signal)
        if (step === 'templates') return updateTemplates(progress, controller!.signal)
        return installJava(progress, controller!.signal)
      })
      console.log(`[auto-setup] done: ${step}`)
    }
    if (controller.signal.aborted) {
      set({ running: false, step: undefined, error: 'Stopped. Setup will try again next time you open SiteWarden, or install from the Deep scanners page.' })
    } else {
      const doneAt = new Date().toISOString()
      store.set('autoSetupDoneAt', doneAt)
      set({ running: false, step: undefined, doneAt })
    }
  } catch (e) {
    const msg = controller.signal.aborted ? 'Stopped.' : (e as Error).message
    console.log(`[auto-setup] failed: ${msg}`)
    set({ running: false, step: undefined, error: `${msg} It will try again next time you open SiteWarden.` })
  } finally {
    controller = null
  }
}
