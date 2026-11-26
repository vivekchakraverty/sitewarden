// Finds, installs and configures the deep-scan tools:
//  - Nuclei: official release from GitHub, verified against the release's checksums file
//  - Java 17+: needed by ZAP; found on the system or installed as a private Temurin 21 JRE (checksum from Adoptium)
//  - OWASP ZAP: detected from the usual install folders or chosen by the user (not downloaded: it has its own installer)
import { app } from 'electron'
import { spawn } from 'child_process'
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from 'fs'
import { join } from 'path'
import type { ScannerSettings, ToolProgress, ToolsStatus } from '../../shared/types'
import { store } from '../store'
import { extractTarGz, extractZip } from './archive'
import { downloadVerified, fetchJson, fetchText } from './download'

interface Saved {
  nuclei?: { version: string; path: string }
  templatesAt?: string
  java?: { path: string; version: number }
  zapDir?: string
}

export const DEFAULT_SETTINGS: ScannerSettings = {
  nucleiRate: 20,
  nucleiMaxMinutes: 30,
  nucleiInteractsh: false,
  zapSpiderMinutes: 3,
  zapMaxMinutes: 15,
  autoInstall: true
}

const saved = (): Saved => store.get<Saved>('tools') ?? {}
const save = (s: Saved): void => store.set('tools', s)
const exe = (name: string): string => (process.platform === 'win32' ? `${name}.exe` : name)

export function toolsDir(): string {
  const d = join(app.getPath('userData'), 'tools')
  mkdirSync(d, { recursive: true })
  return d
}
export const templatesDir = (): string => join(toolsDir(), 'nuclei-templates')

export function settings(): ScannerSettings {
  return { ...DEFAULT_SETTINGS, ...(store.get<Partial<ScannerSettings>>('scannerSettings') ?? {}) }
}

export function saveSettings(s: ScannerSettings): void {
  const clamp = (v: unknown, lo: number, hi: number, d: number): number => {
    const n = Number(v)
    return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : d
  }
  store.set('scannerSettings', {
    nucleiRate: clamp(s.nucleiRate, 1, 150, DEFAULT_SETTINGS.nucleiRate),
    nucleiMaxMinutes: clamp(s.nucleiMaxMinutes, 2, 120, DEFAULT_SETTINGS.nucleiMaxMinutes),
    nucleiInteractsh: s.nucleiInteractsh === true,
    zapSpiderMinutes: clamp(s.zapSpiderMinutes, 1, 30, DEFAULT_SETTINGS.zapSpiderMinutes),
    zapMaxMinutes: clamp(s.zapMaxMinutes, 3, 120, DEFAULT_SETTINGS.zapMaxMinutes),
    autoInstall: s.autoInstall !== false
  } satisfies ScannerSettings)
}

// ---------- install lock (shared by the Scanners page and first-launch setup) ----------

let installing: string | null = null

export function installBusy(): string | null {
  return installing
}

export async function withInstallLock<T>(label: string, fn: () => Promise<T>): Promise<T> {
  if (installing) throw new Error(`Wait for the current setup step to finish (${installing}).`)
  installing = label
  try {
    return await fn()
  } finally {
    installing = null
  }
}

// ---------- process helper ----------

export interface RunResult {
  code: number | null
  stdout: string
  stderr: string
}

export function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs?: number; signal?: AbortSignal; onStdout?: (line: string) => void; onStderr?: (line: string) => void } = {}
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, windowsHide: true, shell: false })
    let stdout = ''
    let stderr = ''
    const lines = (cb?: (l: string) => void) => {
      let rest = ''
      return (chunk: Buffer): string => {
        const text = chunk.toString('utf8')
        if (cb) {
          const parts = (rest + text).split(/\r?\n/)
          rest = parts.pop() ?? ''
          for (const l of parts) if (l.trim()) cb(l)
        }
        return text
      }
    }
    const out = lines(opts.onStdout)
    const err = lines(opts.onStderr)
    child.stdout.on('data', (c: Buffer) => {
      stdout += out(c)
      if (stdout.length > 20_000_000) stdout = stdout.slice(-10_000_000)
    })
    child.stderr.on('data', (c: Buffer) => {
      stderr += err(c)
      if (stderr.length > 2_000_000) stderr = stderr.slice(-1_000_000)
    })
    const kill = (): void => {
      if (!child.killed) child.kill(process.platform === 'win32' ? undefined : 'SIGTERM')
    }
    const timer = opts.timeoutMs ? setTimeout(kill, opts.timeoutMs) : null
    opts.signal?.addEventListener('abort', kill, { once: true })
    child.on('error', (e) => {
      if (timer) clearTimeout(timer)
      reject(e)
    })
    child.on('close', (code) => {
      if (timer) clearTimeout(timer)
      opts.signal?.removeEventListener('abort', kill)
      resolve({ code, stdout, stderr })
    })
  })
}

// ---------- Java ----------

export function parseJavaVersion(text: string): number | null {
  const m = /version "(\d+)(?:\.(\d+))?/.exec(text)
  if (!m) return null
  const major = Number(m[1])
  return major === 1 ? Number(m[2]) : major
}

async function javaVersion(path: string): Promise<number | null> {
  if (!existsSync(path)) return null
  try {
    const r = await run(path, ['-version'], { timeoutMs: 15000 })
    return parseJavaVersion(r.stderr + r.stdout)
  } catch {
    return null
  }
}

function javaCandidates(): string[] {
  const c: string[] = []
  const s = saved()
  if (s.java?.path) c.push(s.java.path)
  const zap = zapInfo()
  if (zap.dir) {
    // The Windows/macOS installers record the Java they were set up with.
    const cfg = join(zap.dir, '.install4j', 'inst_jre.cfg')
    if (existsSync(cfg)) c.push(join(readFileSync(cfg, 'utf8').trim(), 'bin', exe('java')))
  }
  if (zap.dir && process.platform === 'darwin') {
    // The macOS ZAP.app bundles its own Java under Contents/PlugIns.
    const plugins = join(zap.dir, '..', 'PlugIns')
    if (existsSync(plugins)) for (const d of readdirSync(plugins)) c.push(join(plugins, d, 'Contents', 'Home', 'bin', 'java'))
  }
  if (process.env.JAVA_HOME) c.push(join(process.env.JAVA_HOME, 'bin', exe('java')))
  const roots =
    process.platform === 'win32'
      ? ['C:\\Program Files\\Java', 'C:\\Program Files\\Eclipse Adoptium', 'C:\\Program Files\\Microsoft', 'C:\\Program Files\\Zulu', 'C:\\Program Files\\Amazon Corretto']
      : process.platform === 'darwin'
        ? ['/Library/Java/JavaVirtualMachines']
        : ['/usr/lib/jvm']
  for (const r of roots) {
    if (!existsSync(r)) continue
    for (const d of readdirSync(r)) {
      c.push(process.platform === 'darwin' ? join(r, d, 'Contents', 'Home', 'bin', 'java') : join(r, d, 'bin', exe('java')))
    }
  }
  c.push(exe('java')) // PATH
  return [...new Set(c)]
}

export async function findJava(): Promise<{ path: string; version: number } | null> {
  for (const p of javaCandidates()) {
    const v = p === exe('java') ? await javaOnPath() : await javaVersion(p)
    if (v && v >= 17) return { path: p, version: v }
  }
  return null
}

async function javaOnPath(): Promise<number | null> {
  try {
    const r = await run(exe('java'), ['-version'], { timeoutMs: 15000 })
    return parseJavaVersion(r.stderr + r.stdout)
  } catch {
    return null
  }
}

function findFile(dir: string, name: string, depth = 4): string | null {
  if (depth < 0 || !existsSync(dir)) return null
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name)
    if (e.isFile() && e.name === name && /[\\/]bin$/.test(dir)) return p
    if (e.isDirectory()) {
      const f = findFile(p, name, depth - 1)
      if (f) return f
    }
  }
  return null
}

export async function installJava(progress: (p: ToolProgress) => void, signal?: AbortSignal): Promise<void> {
  const os = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'mac' : 'linux'
  const arch = process.arch === 'arm64' ? 'aarch64' : 'x64'
  progress({ tool: 'java', message: 'Looking up the latest Temurin 21 JRE…' })
  const assets = await fetchJson<{ release_name: string; binary: { package: { link: string; checksum: string; size: number; name: string } } }[]>(
    `https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=${arch}&image_type=jre&os=${os}&vendor=eclipse`
  )
  const a = assets.find((x) => /\.(zip|tar\.gz)$/.test(x.binary.package.name))
  if (!a) throw new Error('No Temurin JRE build found for this platform.')
  const pkg = a.binary.package
  const buf = await downloadVerified(pkg.link, pkg.checksum, {
    maxBytes: Math.max(pkg.size * 1.1, 10_000_000),
    signal,
    onProgress: (d, t) => progress({ tool: 'java', message: `Downloading ${pkg.name}`, pct: t ? Math.round((d / t) * 100) : undefined })
  })
  progress({ tool: 'java', message: 'Checksum verified. Extracting…' })
  const dest = join(toolsDir(), 'java', a.release_name.replace(/[^\w.+-]/g, '_'))
  rmSync(dest, { recursive: true, force: true })
  mkdirSync(dest, { recursive: true })
  if (pkg.name.endsWith('.zip')) extractZip(buf, dest)
  else extractTarGz(buf, dest)
  const java = findFile(dest, exe('java'), 5)
  if (!java) throw new Error('Java was downloaded but its executable was not found.')
  if (process.platform !== 'win32') chmodSync(java, 0o755)
  const version = await javaVersion(java)
  if (!version || version < 17) throw new Error('The downloaded Java did not start.')
  save({ ...saved(), java: { path: java, version } })
  progress({ tool: 'java', message: `Java ${version} installed.`, pct: 100 })
}

// ---------- ZAP ----------

function zapDirs(): string[] {
  const s = saved()
  const list: string[] = []
  if (s.zapDir) list.push(s.zapDir)
  if (process.platform === 'win32') {
    list.push('C:\\Program Files\\ZAP\\Zed Attack Proxy', 'C:\\Program Files\\OWASP\\Zed Attack Proxy', 'C:\\Program Files (x86)\\ZAP\\Zed Attack Proxy')
  } else if (process.platform === 'darwin') {
    list.push('/Applications/ZAP.app/Contents/Java', '/Applications/OWASP ZAP.app/Contents/Java')
  } else {
    list.push('/usr/share/zaproxy', '/opt/zaproxy', '/snap/zaproxy/current')
  }
  return list
}

const cmpVersion = (a: string, b: string): number => {
  const x = a.split('.').map(Number)
  const y = b.split('.').map(Number)
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0)
  return 0
}

export function zapInfo(): ToolsStatus['zap'] {
  const custom = Boolean(saved().zapDir)
  for (const dir of zapDirs()) {
    if (!existsSync(dir)) continue
    const jars = readdirSync(dir)
      .map((f) => /^zap-(\d+\.\d+\.\d+)\.jar$/.exec(f))
      .filter((m): m is RegExpExecArray => Boolean(m))
      .sort((a, b) => cmpVersion(b[1], a[1]))
    if (jars.length) return { found: true, dir, jar: join(dir, jars[0][0]), version: jars[0][1], custom }
  }
  return { found: false, custom }
}

export function setZapDir(dir: string | undefined): void {
  if (dir) {
    const has = existsSync(dir) && readdirSync(dir).some((f) => /^zap-\d+\.\d+\.\d+\.jar$/.test(f))
    if (!has) throw new Error('That folder has no zap-<version>.jar. Pick the ZAP installation folder.')
  }
  save({ ...saved(), zapDir: dir })
}

// ---------- Nuclei ----------

interface GhRelease {
  tag_name: string
  assets: { name: string; browser_download_url: string; size: number }[]
}

export function nucleiAssetSuffix(platform = process.platform, arch = process.arch): string {
  const a = arch === 'arm64' ? 'arm64' : 'amd64'
  const os = platform === 'win32' ? 'windows' : platform === 'darwin' ? 'macOS' : 'linux'
  return `_${os}_${a}.zip`
}

export function parseChecksums(text: string): Map<string, string> {
  const m = new Map<string, string>()
  for (const line of text.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/)
    if (parts.length >= 2 && /^[0-9a-f]{64}$/i.test(parts[0])) m.set(parts[parts.length - 1].replace(/^\*/, ''), parts[0])
  }
  return m
}

export async function installNuclei(progress: (p: ToolProgress) => void, signal?: AbortSignal): Promise<void> {
  progress({ tool: 'nuclei', message: 'Looking up the latest Nuclei release…' })
  const rel = await fetchJson<GhRelease>('https://api.github.com/repos/projectdiscovery/nuclei/releases/latest')
  const suffix = nucleiAssetSuffix()
  const asset = rel.assets.find((a) => a.name.startsWith('nuclei_') && a.name.endsWith(suffix))
  const sums = rel.assets.find((a) => /checksums\.txt$/.test(a.name))
  if (!asset || !sums) throw new Error(`No Nuclei build for this platform in release ${rel.tag_name}.`)
  const checksum = parseChecksums(await fetchText(sums.browser_download_url)).get(asset.name)
  if (!checksum) throw new Error('The release checksums file does not list this build; refusing to install.')
  const buf = await downloadVerified(asset.browser_download_url, checksum, {
    maxBytes: Math.max(asset.size * 1.1, 5_000_000),
    signal,
    onProgress: (d, t) => progress({ tool: 'nuclei', message: `Downloading ${asset.name}`, pct: t ? Math.round((d / t) * 100) : undefined })
  })
  progress({ tool: 'nuclei', message: 'Checksum verified. Extracting…' })
  const version = rel.tag_name.replace(/^v/, '')
  const dest = join(toolsDir(), 'nuclei', version.replace(/[^\w.-]/g, '_'))
  rmSync(dest, { recursive: true, force: true })
  mkdirSync(dest, { recursive: true })
  extractZip(buf, dest)
  const bin = join(dest, exe('nuclei'))
  if (!existsSync(bin)) throw new Error('Nuclei was downloaded but the executable was not in the archive.')
  // Zip entries don't always carry Unix permissions; make sure the binary can run on macOS/Linux.
  if (process.platform !== 'win32') chmodSync(bin, 0o755)
  const v = await run(bin, ['-version', '-duc'], { timeoutMs: 30000 })
  if (!/Nuclei Engine Version/i.test(v.stderr + v.stdout)) throw new Error(`Nuclei did not start: ${(v.stderr || v.stdout).slice(0, 300)}`)
  save({ ...saved(), nuclei: { version, path: bin } })
  progress({ tool: 'nuclei', message: `Nuclei ${version} installed.`, pct: 100 })
  await updateTemplates(progress, signal)
}

export async function updateTemplates(progress: (p: ToolProgress) => void, signal?: AbortSignal): Promise<void> {
  const n = saved().nuclei
  if (!n || !existsSync(n.path)) throw new Error('Install Nuclei first.')
  progress({ tool: 'templates', message: 'Downloading Nuclei templates (this can take a few minutes)…' })
  mkdirSync(templatesDir(), { recursive: true })
  const r = await run(n.path, ['-ut', '-ud', templatesDir(), '-nc'], {
    timeoutMs: 15 * 60_000,
    signal,
    onStderr: (l) => progress({ tool: 'templates', message: l.replace(/^\[\w+\]\s*/, '').slice(0, 160) })
  })
  if (signal?.aborted) throw new Error('Stopped')
  const count = countTemplates()
  if (!count) throw new Error(`Template update failed: ${(r.stderr || r.stdout).trim().split('\n').slice(-3).join(' ').slice(0, 400)}`)
  save({ ...saved(), templatesAt: new Date().toISOString() })
  progress({ tool: 'templates', message: `${count} templates ready.`, pct: 100 })
}

function countTemplates(dir = templatesDir(), depth = 6): number {
  if (depth < 0 || !existsSync(dir)) return 0
  let n = 0
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith('.')) continue
    if (e.isDirectory()) n += countTemplates(join(dir, e.name), depth - 1)
    else if (e.name.endsWith('.yaml')) n++
  }
  return n
}

export function templatesUpdatedAt(): string | undefined {
  return saved().templatesAt
}

export function nucleiPath(): string | null {
  const n = saved().nuclei
  return n && existsSync(n.path) ? n.path : null
}

export function removeTool(tool: 'nuclei' | 'java'): void {
  const s = saved()
  if (tool === 'nuclei') {
    rmSync(join(toolsDir(), 'nuclei'), { recursive: true, force: true })
    rmSync(templatesDir(), { recursive: true, force: true })
    save({ ...s, nuclei: undefined, templatesAt: undefined })
  } else {
    rmSync(join(toolsDir(), 'java'), { recursive: true, force: true })
    save({ ...s, java: undefined })
  }
}

// ---------- status ----------

let templateCountCache: { at: string; count: number } | null = null

export async function status(): Promise<ToolsStatus> {
  const s = saved()
  const java = await findJava()
  const managedRoot = join(toolsDir(), 'java')
  if (s.templatesAt && templateCountCache?.at !== s.templatesAt) templateCountCache = { at: s.templatesAt, count: countTemplates() }
  const nucleiOk = Boolean(s.nuclei && existsSync(s.nuclei.path))
  return {
    nuclei: {
      installed: nucleiOk,
      version: nucleiOk ? s.nuclei!.version : undefined,
      path: nucleiOk ? s.nuclei!.path : undefined,
      templatesUpdatedAt: s.templatesAt,
      templateCount: templateCountCache?.count
    },
    java: java
      ? { ok: true, path: java.path, version: java.version, managed: java.path.startsWith(managedRoot) }
      : { ok: false, managed: false, note: 'ZAP needs Java 17 or newer, and none was found.' },
    zap: zapInfo(),
    settings: settings()
  }
}
