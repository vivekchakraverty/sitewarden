// Smoke test for the checks that don't need Electron. Usage: npm run smoke -- <host you own>
// Runs passive checks only (no sensitive-path probing), plus a fix-library coverage check.
import { readFileSync, readdirSync } from 'fs'
import { join } from 'path'
import { FIXES } from '../src/main/fixes'
import { get } from '../src/main/http'
import { contentCheck } from '../src/main/scanners/content'
import { dnsCheck } from '../src/main/scanners/dnsmail'
import { cookiesCheck, headersCheck } from '../src/main/scanners/headers'
import { transportCheck } from '../src/main/scanners/transport'
import type { ScanContext } from '../src/main/scanners/types'

const dir = join(__dirname, '..', 'src', 'main', 'scanners')
const used = new Set<string>()
for (const f of readdirSync(dir)) {
  for (const m of readFileSync(join(dir, f), 'utf8').matchAll(/fixId: '([\w-]+)'/g)) used.add(m[1])
}
const missing = [...used].filter((id) => !FIXES[id])
console.log(`fix library: ${used.size} fixIds referenced, ${missing.length} missing${missing.length ? ': ' + missing.join(', ') : ''}`)

async function main(): Promise<void> {
  const host = process.argv[2] ?? 'example.com'
  const ctx: ScanContext = { host, key: () => undefined, signal: new AbortController().signal, note: () => undefined }
  try { ctx.home = await get(`https://${host}/`) } catch (e) { ctx.homeError = (e as Error).message }
  for (const c of [transportCheck, headersCheck, cookiesCheck, contentCheck, dnsCheck]) {
    try {
      const out = await c.run(ctx)
      if (!Array.isArray(out)) { console.log(`\n[${c.name}] skipped: ${out.skipped}`); continue }
      console.log(`\n[${c.name}] ${out.length} finding(s)`)
      for (const f of out) console.log(`  ${f.severity.padEnd(8)} ${f.title}`)
    } catch (e) {
      console.log(`\n[${c.name}] ERROR ${(e as Error).message}`)
    }
  }
  if (missing.length) process.exit(1)
}
void main()
