import { app, BrowserWindow, dialog, ipcMain, shell } from 'electron'
import { writeFileSync } from 'fs'
import { join } from 'path'
import { electronApp, is, optimizer } from '@electron-toolkit/utils'
import type { DeepOptions, DeployOptions, KeyName, ScannerSettings, ToolProgress, VmSettings } from '../shared/types'
import { agentAck, agentApprove, agentSummary, guardSnippet } from './cloudflare/agent'
import { connect as cfConnect, deploy as cfDeploy, disconnect as cfDisconnect, removeAgent, status as cfStatus } from './cloudflare/deploy'
import { applyCspFix, applyItems, cspCheck, hardening, revert } from './cloudflare/hardening'
import { addDomain, verifyDomain } from './domains'
import { getFix } from './fixes'
import { renderReport } from './report'
import { cancelScan, runScan } from './scanners'
import * as tools from './tools/manager'
import { autoSetupState, runAutoSetup, stopAutoSetup } from './tools/autosetup'
import * as vm from './oracle/vm'
import { clearKey, encryptionAvailable, listKeys, setKey } from './secrets'
import { store } from './store'

let win: BrowserWindow | null = null

function createWindow(): void {
  win = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    show: false,
    title: 'SiteWarden',
    autoHideMenuBar: true,
    backgroundColor: '#0f1419',
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false
    }
  })
  win.on('ready-to-show', () => win?.show())

  // Never open other pages inside the app window; send http(s) links to the browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//.test(url)) void shell.openExternal(url)
    return { action: 'deny' }
  })
  win.webContents.on('will-navigate', (e, url) => {
    if (url !== win?.webContents.getURL()) e.preventDefault()
  })

  if (is.dev && process.env['ELECTRON_RENDERER_URL']) void win.loadURL(process.env['ELECTRON_RENDERER_URL'])
  else void win.loadFile(join(__dirname, '../renderer/index.html'))
}

const KEY_NAMES: KeyName[] = ['safeBrowsing', 'virusTotal', 'urlhaus']
const asKeyName = (n: unknown): KeyName => {
  if (!KEY_NAMES.includes(n as KeyName)) throw new Error('Unknown key name')
  return n as KeyName
}
const asString = (v: unknown, max = 4096): string => {
  if (typeof v !== 'string' || v.length > max) throw new Error('Invalid input')
  return v
}

function registerIpc(): void {
  ipcMain.handle('domains:list', () => store.domains())
  ipcMain.handle('domains:add', (_e, input: unknown) => addDomain(asString(input, 300)))
  ipcMain.handle('domains:remove', (_e, id: unknown) => store.removeDomain(asString(id, 64)))
  ipcMain.handle('domains:verify', (_e, id: unknown) => verifyDomain(asString(id, 64)))

  ipcMain.handle('keys:list', () => listKeys())
  ipcMain.handle('keys:set', (_e, name: unknown, value: unknown) => setKey(asKeyName(name), asString(value)))
  ipcMain.handle('keys:clear', (_e, name: unknown) => clearKey(asKeyName(name)))
  ipcMain.handle('keys:encryptionAvailable', () => encryptionAvailable())

  ipcMain.handle('scan:run', (e, id: unknown, deep: unknown) => {
    const d = (deep ?? {}) as Partial<DeepOptions>
    return runScan(
      asString(id, 64),
      (p) => {
        if (!e.sender.isDestroyed()) e.sender.send('scan:progress', p)
      },
      { nuclei: d.nuclei === true, zap: d.zap === true }
    )
  })
  ipcMain.handle('scan:cancel', (_e, id: unknown) => cancelScan(asString(id, 64)))

  // Tool installs are long; the lock is shared with first-launch setup.
  const install = async (e: Electron.IpcMainInvokeEvent, label: string, fn: (p: (x: ToolProgress) => void) => Promise<void>) => {
    await tools.withInstallLock(label, () =>
      fn((p) => {
        if (!e.sender.isDestroyed()) e.sender.send('tools:progress', p)
      })
    )
    return tools.status()
  }
  ipcMain.handle('tools:status', () => tools.status())
  ipcMain.handle('tools:installNuclei', (e) => install(e, 'Installing Nuclei', (p) => tools.installNuclei(p)))
  ipcMain.handle('tools:updateTemplates', (e) => install(e, 'Updating templates', (p) => tools.updateTemplates(p)))
  ipcMain.handle('tools:installJava', (e) => install(e, 'Installing Java', (p) => tools.installJava(p)))
  ipcMain.handle('tools:chooseZapDir', async () => {
    if (!win) return tools.status()
    const r = await dialog.showOpenDialog(win, { title: 'Choose the OWASP ZAP installation folder', properties: ['openDirectory'] })
    if (!r.canceled && r.filePaths[0]) tools.setZapDir(r.filePaths[0])
    return tools.status()
  })
  ipcMain.handle('tools:resetZapDir', () => {
    tools.setZapDir(undefined)
    return tools.status()
  })
  ipcMain.handle('tools:remove', (_e, t: unknown) => {
    if (t !== 'nuclei' && t !== 'java') throw new Error('Invalid input')
    if (tools.installBusy()) throw new Error('Wait for the current install to finish.')
    tools.removeTool(t)
    return tools.status()
  })
  ipcMain.handle('tools:autoState', () => autoSetupState())
  ipcMain.handle('tools:stopAuto', () => stopAutoSetup())
  ipcMain.handle('tools:saveSettings', (_e, s: unknown) => {
    tools.saveSettings((s ?? {}) as ScannerSettings)
    return tools.status()
  })
  ipcMain.handle('scans:list', (_e, id: unknown) => store.scans(asString(id, 64)))
  ipcMain.handle('report:export', async (_e, scanId: unknown) => {
    const scan = store.scan(asString(scanId, 64))
    if (!scan || !win) return null
    const stamp = scan.startedAt.slice(0, 10)
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: 'Save security report',
      defaultPath: `sitewarden-${scan.host}-${stamp}.html`,
      filters: [{ name: 'HTML report', extensions: ['html'] }]
    })
    if (canceled || !filePath) return null
    writeFileSync(filePath, renderReport(scan), 'utf8')
    return filePath
  })

  ipcMain.handle('cf:status', () => cfStatus())
  ipcMain.handle('cf:connect', (_e, t: unknown) => cfConnect(asString(t, 200)))
  ipcMain.handle('cf:disconnect', () => cfDisconnect())
  ipcMain.handle('cf:deploy', (_e, o: unknown) => {
    const opts = (o ?? {}) as Partial<DeployOptions>
    return cfDeploy({
      accountId: asString(opts.accountId, 64),
      alertWebhook: opts.alertWebhook === undefined ? undefined : asString(opts.alertWebhook, 1000),
      copyKeys: opts.copyKeys === true
    })
  })
  ipcMain.handle('cf:removeAgent', () => removeAgent())
  ipcMain.handle('cf:hardening', (_e, id: unknown) => hardening(asString(id, 64)))
  ipcMain.handle('cf:apply', (_e, id: unknown, items: unknown) => {
    if (!Array.isArray(items) || items.length > 20) throw new Error('Invalid input')
    return applyItems(asString(id, 64), items.map((i) => asString(i, 64)))
  })
  ipcMain.handle('cf:changes', (_e, id: unknown) => store.changes(asString(id, 64)))
  ipcMain.handle('cf:revert', (_e, changeId: unknown) => {
    if (typeof changeId !== 'number' || !Number.isInteger(changeId)) throw new Error('Invalid input')
    return revert(changeId)
  })
  ipcMain.handle('csp:check', (_e, id: unknown) => cspCheck(asString(id, 64)))
  ipcMain.handle('csp:fix', (_e, id: unknown) => applyCspFix(asString(id, 64)))
  ipcMain.handle('agent:summary', (_e, id: unknown) => agentSummary(asString(id, 64)))
  ipcMain.handle('agent:approve', (_e, id: unknown, origin: unknown, approved: unknown) =>
    agentApprove(asString(id, 64), asString(origin, 300), approved === true)
  )
  ipcMain.handle('agent:ack', (_e, id: unknown) => agentAck(asString(id, 64)))
  ipcMain.handle('agent:snippet', (_e, id: unknown) => guardSnippet(asString(id, 64)))

  ipcMain.handle('vm:status', () => vm.status())
  ipcMain.handle('vm:setup', () => vm.setup())
  ipcMain.handle('vm:cloudInit', () => vm.cloudInit())
  ipcMain.handle('vm:saveCloudInit', async () => {
    const text = vm.cloudInit()
    if (!win) return null
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: 'Save cloud-init for the Oracle VM (contains a secret token)',
      defaultPath: 'sitewarden-cloud-init.yaml',
      filters: [{ name: 'cloud-init YAML', extensions: ['yaml', 'yml'] }]
    })
    if (canceled || !filePath) return null
    writeFileSync(filePath, text, { encoding: 'utf8', mode: 0o600 })
    return filePath
  })
  ipcMain.handle('vm:rotateToken', () => vm.rotateToken())
  ipcMain.handle('vm:scanNow', (_e, id: unknown) => vm.scanNow(asString(id, 64)))
  ipcMain.handle('vm:saveSettings', (_e, s: unknown) => vm.saveSettings((s ?? {}) as VmSettings))
  ipcMain.handle('vm:import', () => vm.importResults())

  ipcMain.handle('fix:get', (_e, id: unknown) => getFix(asString(id, 64)))
  ipcMain.handle('shell:openExternal', (_e, url: unknown) => {
    const u = asString(url, 2048)
    if (!/^https:\/\//.test(u)) throw new Error('Only https links can be opened')
    return shell.openExternal(u)
  })
}

app.whenReady().then(() => {
  electronApp.setAppUserModelId('app.sitewarden.desktop')
  app.on('browser-window-created', (_, w) => optimizer.watchWindowShortcuts(w))
  registerIpc()
  createWindow()
  // First launch after install (and weekly afterwards): fetch the deep-scan tools in the background.
  const broadcast = (channel: string, payload: unknown): void => {
    for (const w of BrowserWindow.getAllWindows()) if (!w.webContents.isDestroyed()) w.webContents.send(channel, payload)
  }
  setTimeout(() => {
    void runAutoSetup({ progress: (p) => broadcast('tools:progress', p), state: (st) => broadcast('tools:auto', st) })
  }, 3000)
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
