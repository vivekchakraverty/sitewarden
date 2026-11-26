import { contextBridge, ipcRenderer } from 'electron'
import type { AutoSetupState, ScanProgress, SiteWardenApi, ToolProgress } from '../shared/types'

const api: SiteWardenApi = {
  listDomains: () => ipcRenderer.invoke('domains:list'),
  addDomain: (input) => ipcRenderer.invoke('domains:add', input),
  removeDomain: (id) => ipcRenderer.invoke('domains:remove', id),
  verifyDomain: (id) => ipcRenderer.invoke('domains:verify', id),

  listKeys: () => ipcRenderer.invoke('keys:list'),
  setKey: (name, value) => ipcRenderer.invoke('keys:set', name, value),
  clearKey: (name) => ipcRenderer.invoke('keys:clear', name),
  encryptionAvailable: () => ipcRenderer.invoke('keys:encryptionAvailable'),

  runScan: (id, deep) => ipcRenderer.invoke('scan:run', id, deep),
  cancelScan: (id) => ipcRenderer.invoke('scan:cancel', id),
  listScans: (id) => ipcRenderer.invoke('scans:list', id),
  exportReport: (scanId) => ipcRenderer.invoke('report:export', scanId),
  onScanProgress: (cb) => {
    const listener = (_e: unknown, p: ScanProgress): void => cb(p)
    ipcRenderer.on('scan:progress', listener)
    return () => ipcRenderer.removeListener('scan:progress', listener)
  },

  getFix: (id) => ipcRenderer.invoke('fix:get', id),
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),

  cfStatus: () => ipcRenderer.invoke('cf:status'),
  cfConnect: (token) => ipcRenderer.invoke('cf:connect', token),
  cfDisconnect: () => ipcRenderer.invoke('cf:disconnect'),
  cfDeploy: (opts) => ipcRenderer.invoke('cf:deploy', opts),
  cfRemoveAgent: () => ipcRenderer.invoke('cf:removeAgent'),
  cfHardening: (id) => ipcRenderer.invoke('cf:hardening', id),
  cfApply: (id, items) => ipcRenderer.invoke('cf:apply', id, items),
  cfChanges: (id) => ipcRenderer.invoke('cf:changes', id),
  cfRevert: (changeId) => ipcRenderer.invoke('cf:revert', changeId),

  cspCheck: (id) => ipcRenderer.invoke('csp:check', id),
  cspFix: (id) => ipcRenderer.invoke('csp:fix', id),
  agentSummary: (id) => ipcRenderer.invoke('agent:summary', id),
  agentApprove: (id, origin, approved) => ipcRenderer.invoke('agent:approve', id, origin, approved),
  agentAckAlerts: (id) => ipcRenderer.invoke('agent:ack', id),
  guardSnippet: (id) => ipcRenderer.invoke('agent:snippet', id),

  toolsStatus: () => ipcRenderer.invoke('tools:status'),
  installNuclei: () => ipcRenderer.invoke('tools:installNuclei'),
  updateTemplates: () => ipcRenderer.invoke('tools:updateTemplates'),
  installJava: () => ipcRenderer.invoke('tools:installJava'),
  chooseZapDir: () => ipcRenderer.invoke('tools:chooseZapDir'),
  resetZapDir: () => ipcRenderer.invoke('tools:resetZapDir'),
  removeTool: (t) => ipcRenderer.invoke('tools:remove', t),
  saveScannerSettings: (s) => ipcRenderer.invoke('tools:saveSettings', s),
  onToolProgress: (cb) => {
    const listener = (_e: unknown, p: ToolProgress): void => cb(p)
    ipcRenderer.on('tools:progress', listener)
    return () => ipcRenderer.removeListener('tools:progress', listener)
  },
  vmStatus: () => ipcRenderer.invoke('vm:status'),
  vmSetup: () => ipcRenderer.invoke('vm:setup'),
  vmCloudInit: () => ipcRenderer.invoke('vm:cloudInit'),
  vmSaveCloudInit: () => ipcRenderer.invoke('vm:saveCloudInit'),
  vmRotateToken: () => ipcRenderer.invoke('vm:rotateToken'),
  vmScanNow: (id) => ipcRenderer.invoke('vm:scanNow', id),
  vmSaveSettings: (s) => ipcRenderer.invoke('vm:saveSettings', s),
  vmImport: () => ipcRenderer.invoke('vm:import'),
  autoSetupState: () => ipcRenderer.invoke('tools:autoState'),
  stopAutoSetup: () => ipcRenderer.invoke('tools:stopAuto'),
  onAutoSetup: (cb) => {
    const listener = (_e: unknown, s: AutoSetupState): void => cb(s)
    ipcRenderer.on('tools:auto', listener)
    return () => ipcRenderer.removeListener('tools:auto', listener)
  }
}

contextBridge.exposeInMainWorld('sitewarden', api)
