// Types shared by the main process, preload bridge and renderer.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Domain {
  id: string
  host: string
  addedAt: string
  /** Token the user must publish (DNS TXT or meta tag) to prove ownership. */
  verificationToken: string
  verified: boolean
  verifiedAt?: string
  verifiedBy?: 'dns' | 'meta'
}

export interface Finding {
  /** Stable id of the check that produced this, e.g. "headers.hsts". */
  checkId: string
  severity: Severity
  title: string
  detail: string
  evidence?: string
  /** Key into the fix library; absent when there is nothing to fix. */
  fixId?: string
  /** Fix text supplied by an external scanner (Nuclei / ZAP) when there is no library entry. */
  remediation?: string
  references?: string[]
  source?: 'nuclei' | 'zap'
}

export type CheckStatus = 'ok' | 'issues' | 'skipped' | 'error'

export interface CheckRun {
  id: string
  name: string
  status: CheckStatus
  /** Why it was skipped or what went wrong. */
  note?: string
  durationMs: number
}

export interface ScanResult {
  id: string
  domainId: string
  host: string
  startedAt: string
  finishedAt: string
  score: number
  grade: string
  findings: Finding[]
  checks: CheckRun[]
  /** Where the scan ran. Absent means this computer. */
  origin?: 'local' | 'oracle'
}

export type KeyName = 'safeBrowsing' | 'virusTotal' | 'urlhaus'

export interface KeyInfo {
  name: KeyName
  label: string
  signupUrl: string
  help: string
  isSet: boolean
}

export interface ScanProgress {
  domainId: string
  checkId: string
  checkName: string
  done: number
  total: number
  /** Live detail from long-running scanners, e.g. "Nuclei 42% · 3 findings". */
  note?: string
}

export interface VerifyOutcome {
  ok: boolean
  method?: 'dns' | 'meta'
  message: string
}

export interface FixStep {
  platform: string
  code?: string
  text?: string
}

export interface Fix {
  id: string
  title: string
  why: string
  steps: FixStep[]
  references?: string[]
}

// ---------- Phase 2: Cloudflare ----------

export interface CfAccount {
  id: string
  name: string
}

export interface CfStatus {
  connected: boolean
  accounts: CfAccount[]
  accountId?: string
  /** https://sitewarden-agent.<subdomain>.workers.dev once deployed */
  workerUrl?: string
  deployedAt?: string
  deployedSites: string[]
  alertWebhookSet: boolean
  keysCopied: boolean
}

export interface DeployOptions {
  accountId: string
  /** Slack- or Discord-compatible incoming webhook. Empty string removes it. */
  alertWebhook?: string
  /** Copy the Safe Browsing / URLhaus keys into the Worker for 24/7 checks. */
  copyKeys: boolean
}

export interface DeployResult {
  workerUrl: string
  sites: string[]
  steps: string[]
}

export interface HardeningItem {
  id: string
  label: string
  description: string
  warning?: string
  current: string
  recommended: string
  /** Already at the recommended value. */
  done: boolean
  /** False when it can't be read (missing permission, not on this plan, ...). */
  available: boolean
  note?: string
  /** Pre-ticked in the UI. Risky items default to off. */
  recommendedByDefault: boolean
}

export interface ZoneHardening {
  zoneId?: string
  zoneName?: string
  plan?: string
  items: HardeningItem[]
  error?: string
}

export interface ApplyResult {
  id: string
  ok: boolean
  message: string
}

export interface CfChange {
  id: number
  domainId: string
  zoneId: string
  item: string
  label: string
  previous: string
  applied: string
  appliedAt: string
  revertedAt?: string
}

export interface AgentCheck {
  ts: string
  ok: boolean
  status: number
  ms: number
  error?: string
}

export interface AgentOrigin {
  origin: string
  source: string
  firstSeen: string
  lastSeen: string
  hits: number
  approved: boolean
}

export interface AgentCsp {
  directive: string
  blocked: string
  count: number
  lastSeen: string
  sample?: string
}

export interface AgentAlert {
  id: number
  ts: string
  kind: string
  message: string
  acked: boolean
}

export interface AgentSummary {
  checks: AgentCheck[]
  origins: AgentOrigin[]
  csp: AgentCsp[]
  alerts: AgentAlert[]
}

export interface CspCheck {
  /** none: no CSP; allowed: CSP already permits the agent; blocked: fixable by adding the host;
   *  nonce: script-src uses 'strict-dynamic', so a host allowlist is ignored and the tag needs a nonce. */
  status: 'none' | 'allowed' | 'blocked' | 'nonce' | 'error'
  workerOrigin: string
  inHeader: boolean
  inMeta: boolean
  reportOnly: boolean
  /** Plain-language problems, e.g. "script-src blocks guard.js". */
  problems: string[]
  header?: string
  headerPatched?: string
  meta?: string
  metaPatched?: string
  canAutoFix: boolean
  autoFixNote?: string
  error?: string
}

// ---------- Phase 3: deep scanners ----------

export interface DeepOptions {
  nuclei: boolean
  zap: boolean
}

export interface ScannerSettings {
  /** Nuclei requests per second. */
  nucleiRate: number
  nucleiMaxMinutes: number
  /** Out-of-band checks send probe data to ProjectDiscovery's interactsh servers. Off by default. */
  nucleiInteractsh: boolean
  zapSpiderMinutes: number
  zapMaxMinutes: number
  /** Install Nuclei (and Java when ZAP needs it) on first launch, and refresh templates weekly. */
  autoInstall: boolean
}

export interface ToolsStatus {
  nuclei: { installed: boolean; version?: string; path?: string; templatesUpdatedAt?: string; templateCount?: number }
  java: { ok: boolean; path?: string; version?: number; managed: boolean; note?: string }
  zap: { found: boolean; dir?: string; jar?: string; version?: string; custom: boolean }
  settings: ScannerSettings
}

export interface AutoSetupState {
  running: boolean
  /** What it is doing right now, e.g. "Installing Nuclei". */
  step?: string
  /** Last failure; setup retries on the next launch. */
  error?: string
  /** Set once the first full setup has completed. */
  doneAt?: string
}

export interface ToolProgress {
  tool: 'nuclei' | 'templates' | 'java'
  message: string
  pct?: number
}

// ---------- Phase 4: Oracle VM scan agent ----------

export interface VmSettings {
  enabled: boolean
  intervalHours: number
  nucleiRate: number
  nucleiMaxMinutes: number
  nucleiInteractsh: boolean
  zapSpiderMinutes: number
  zapMaxMinutes: number
}

export interface VmStatus {
  /** False until the Cloudflare agent is deployed (it is the VM's mailbox). */
  available: boolean
  reason?: string
  tokenCreated: boolean
  /** The Worker doesn't have the VM token yet; redeploy needed. */
  needsRedeploy: boolean
  heartbeat?: { ts: string; hostname?: string; agentVersion?: string; diskFreeGb?: number | null; state?: string; site?: string }
  settings?: VmSettings
  jobs: { id: number; site: string; requestedAt: string }[]
  latest: { id: number; site: string; finishedAt: string; errors: string[]; high: number }[]
  sites: string[]
}

/** The API the preload script exposes on window.sitewarden. */
export interface SiteWardenApi {
  listDomains(): Promise<Domain[]>
  addDomain(input: string): Promise<Domain>
  removeDomain(id: string): Promise<void>
  verifyDomain(id: string): Promise<VerifyOutcome>

  listKeys(): Promise<KeyInfo[]>
  setKey(name: KeyName, value: string): Promise<void>
  clearKey(name: KeyName): Promise<void>
  encryptionAvailable(): Promise<boolean>

  runScan(domainId: string, deep?: DeepOptions): Promise<ScanResult>
  cancelScan(domainId: string): Promise<void>
  listScans(domainId: string): Promise<ScanResult[]>
  exportReport(scanId: string): Promise<string | null>
  onScanProgress(cb: (p: ScanProgress) => void): () => void

  getFix(fixId: string): Promise<Fix | null>
  openExternal(url: string): Promise<void>

  cfStatus(): Promise<CfStatus>
  cfConnect(token: string): Promise<CfStatus>
  cfDisconnect(): Promise<void>
  cfDeploy(opts: DeployOptions): Promise<DeployResult>
  cfRemoveAgent(): Promise<void>
  cfHardening(domainId: string): Promise<ZoneHardening>
  cfApply(domainId: string, itemIds: string[]): Promise<ApplyResult[]>
  cfChanges(domainId: string): Promise<CfChange[]>
  cfRevert(changeId: number): Promise<ApplyResult>

  cspCheck(domainId: string): Promise<CspCheck>
  cspFix(domainId: string): Promise<{ result: ApplyResult; check: CspCheck }>

  agentSummary(domainId: string): Promise<AgentSummary>
  agentApprove(domainId: string, origin: string, approved: boolean): Promise<void>
  agentAckAlerts(domainId: string): Promise<void>
  guardSnippet(domainId: string): Promise<string | null>

  toolsStatus(): Promise<ToolsStatus>
  installNuclei(): Promise<ToolsStatus>
  updateTemplates(): Promise<ToolsStatus>
  installJava(): Promise<ToolsStatus>
  chooseZapDir(): Promise<ToolsStatus>
  resetZapDir(): Promise<ToolsStatus>
  removeTool(tool: 'nuclei' | 'java'): Promise<ToolsStatus>
  saveScannerSettings(s: ScannerSettings): Promise<ToolsStatus>
  onToolProgress(cb: (p: ToolProgress) => void): () => void
  autoSetupState(): Promise<AutoSetupState>
  stopAutoSetup(): Promise<void>
  onAutoSetup(cb: (s: AutoSetupState) => void): () => void

  vmStatus(): Promise<VmStatus>
  vmSetup(): Promise<VmStatus>
  vmCloudInit(): Promise<string>
  vmSaveCloudInit(): Promise<string | null>
  vmRotateToken(): Promise<{ status: VmStatus; command: string }>
  vmScanNow(domainId: string): Promise<{ alreadyQueued: boolean }>
  vmSaveSettings(s: VmSettings): Promise<VmStatus>
  vmImport(): Promise<number>
}
