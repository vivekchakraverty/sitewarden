// API keys, encrypted with Electron safeStorage (Windows DPAPI / macOS Keychain / libsecret).
// Plaintext keys never leave the main process; the renderer only learns whether a key is set.
import { app, safeStorage } from 'electron'
import { existsSync, readFileSync, renameSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { KeyInfo, KeyName } from '../shared/types'

const KEY_META: Record<KeyName, Omit<KeyInfo, 'name' | 'isSet'>> = {
  safeBrowsing: {
    label: 'Google Safe Browsing API key',
    signupUrl: 'https://developers.google.com/safe-browsing/v4/get-started',
    help: 'Create a Google Cloud project, enable the Safe Browsing API and create an API key. Free for non-commercial use.'
  },
  virusTotal: {
    label: 'VirusTotal API key',
    signupUrl: 'https://www.virustotal.com/gui/join-us',
    help: 'Sign up, then copy the key from your profile > API key. The free public API allows about 4 lookups a minute.'
  },
  urlhaus: {
    label: 'abuse.ch Auth-Key (URLhaus)',
    signupUrl: 'https://auth.abuse.ch/',
    help: 'Sign in at auth.abuse.ch and generate an Auth-Key. Free.'
  }
}

/** Secrets the app manages itself; never listed in the API-keys screen. */
export type InternalSecret = 'cloudflareToken' | 'agentToken' | 'alertWebhook' | 'vmToken'
export type SecretName = KeyName | InternalSecret

type Stored = Partial<Record<SecretName, string>> // base64 ciphertext

function path(): string {
  return join(app.getPath('userData'), 'sitewarden-keys.json')
}

function read(): Stored {
  const p = path()
  if (!existsSync(p)) return {}
  try {
    return JSON.parse(readFileSync(p, 'utf8')) as Stored
  } catch {
    return {}
  }
}

function write(s: Stored): void {
  const tmp = `${path()}.tmp`
  writeFileSync(tmp, JSON.stringify(s, null, 2), { encoding: 'utf8', mode: 0o600 })
  renameSync(tmp, path())
}

export function encryptionAvailable(): boolean {
  if (!safeStorage.isEncryptionAvailable()) return false
  // On Linux without a keyring, Electron falls back to a hard-coded key ("basic_text"), which isn't real protection.
  if (process.platform === 'linux') {
    const backend = (safeStorage as { getSelectedStorageBackend?: () => string }).getSelectedStorageBackend?.()
    if (backend === 'basic_text') return false
  }
  return true
}

export const ENCRYPTION_HELP =
  process.platform === 'linux'
    ? 'No system keyring was found, so keys cannot be stored safely. Install and unlock GNOME Keyring or KWallet (for example: sudo apt install gnome-keyring), then restart SiteWarden.'
    : 'OS encryption is not available, so the key was not saved.'

export function listKeys(): KeyInfo[] {
  const s = read()
  return (Object.keys(KEY_META) as KeyName[]).map((name) => ({
    name,
    ...KEY_META[name],
    isSet: Boolean(s[name])
  }))
}

export function setKey(name: KeyName, value: string): void {
  if (!(name in KEY_META)) throw new Error(`Unknown key: ${name}`)
  setSecret(name, value)
}

export function setSecret(name: SecretName, value: string): void {
  const trimmed = value.trim()
  if (!trimmed) throw new Error('Key is empty')
  if (!encryptionAvailable()) {
    throw new Error(ENCRYPTION_HELP)
  }
  const s = read()
  s[name] = safeStorage.encryptString(trimmed).toString('base64')
  write(s)
}

export function clearKey(name: SecretName): void {
  const s = read()
  delete s[name]
  write(s)
}

/** Main-process only. Returns undefined when the key is not set or cannot be decrypted. */
export function getKey(name: SecretName): string | undefined {
  const enc = read()[name]
  if (!enc) return undefined
  try {
    return safeStorage.decryptString(Buffer.from(enc, 'base64'))
  } catch {
    return undefined
  }
}
