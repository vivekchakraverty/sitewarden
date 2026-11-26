import assert from 'node:assert/strict'
import { createHash } from 'crypto'
import { existsSync, mkdtempSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { deflateRawSync, gzipSync, crc32 } from 'zlib'

let passed = 0
async function t(name: string, fn: () => Promise<void> | void) {
  try {
    await fn()
    passed++
    console.log('  ok  ', name)
  } catch (e) {
    console.log('  FAIL', name, '\n', e)
    process.exitCode = 1
  }
}

process.env.SW_TEST_DIR = mkdtempSync(join(tmpdir(), 'sw3-'))

/** Builds a zip in memory (stored or deflated entries). */
function makeZip(files: { name: string; data: string; deflate?: boolean }[]): Buffer {
  const locals: Buffer[] = []
  const centrals: Buffer[] = []
  let offset = 0
  for (const f of files) {
    const raw = Buffer.from(f.data)
    const comp = f.deflate ? deflateRawSync(raw) : raw
    const name = Buffer.from(f.name)
    const crc = crc32(raw)
    const lh = Buffer.alloc(30)
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(f.deflate ? 8 : 0, 8)
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(name.length, 26)
    const ch = Buffer.alloc(46)
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(f.deflate ? 8 : 0, 10)
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(name.length, 28)
    ch.writeUInt32LE((0o755 << 16) >>> 0, 38); ch.writeUInt32LE(offset, 42)
    locals.push(lh, name, comp)
    centrals.push(ch, name)
    offset += 30 + name.length + comp.length
  }
  const cd = Buffer.concat(centrals)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10)
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(offset, 16)
  return Buffer.concat([...locals, cd, eocd])
}

/** Builds a tar.gz with one long (GNU 'L') name and normal entries. */
function makeTarGz(files: { name: string; data: string; type?: string }[]): Buffer {
  const blocks: Buffer[] = []
  const header = (name: string, size: number, type: string): Buffer => {
    const h = Buffer.alloc(512)
    h.write(name.slice(0, 99), 0)
    h.write('0000755\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116)
    h.write(size.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136)
    h.write('        ', 148); h.write(type, 156); h.write('ustar\0', 257); h.write('00', 263)
    let sum = 0
    for (const b of h) sum += b
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148)
    return h
  }
  const pad = (b: Buffer): Buffer => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)])
  for (const f of files) {
    const data = Buffer.from(f.data)
    if (f.name.length > 99) {
      const ln = Buffer.from(f.name + '\0')
      blocks.push(header('././@LongLink', ln.length, 'L'), pad(ln))
    }
    blocks.push(header(f.name, data.length, f.type ?? '0'), pad(data))
  }
  blocks.push(Buffer.alloc(1024))
  return gzipSync(Buffer.concat(blocks))
}

async function main() {
  const { extractZip, extractTarGz } = await import('../../src/main/tools/archive')
  console.log('archives')
  await t('extracts stored and deflated zip entries', () => {
    const d = mkdtempSync(join(tmpdir(), 'zx-'))
    extractZip(makeZip([{ name: 'bin/', data: '' }, { name: 'bin/tool.txt', data: 'hello' }, { name: 'README.md', data: 'x'.repeat(5000), deflate: true }]), d)
    assert.equal(readFileSync(join(d, 'bin', 'tool.txt'), 'utf8'), 'hello')
    assert.equal(readFileSync(join(d, 'README.md'), 'utf8').length, 5000)
  })
  await t('rejects zip-slip paths', () => {
    const d = mkdtempSync(join(tmpdir(), 'zx-'))
    assert.throws(() => extractZip(makeZip([{ name: '../evil.txt', data: 'pwn' }]), d), /Unsafe path/)
    assert.throws(() => extractZip(makeZip([{ name: 'C:/Windows/evil.txt', data: 'pwn' }]), d), /Unsafe path/)
    assert.ok(!existsSync(join(d, '..', 'evil.txt')))
  })
  await t('extracts tar.gz with GNU long names; rejects traversal', () => {
    const d = mkdtempSync(join(tmpdir(), 'tx-'))
    const long = 'jdk-21.0.5+11-jre/' + 'very-long-directory-name/'.repeat(4) + 'bin/java'
    extractTarGz(makeTarGz([{ name: 'jdk-21.0.5+11-jre/', data: '', type: '5' }, { name: long, data: '#!java' }]), d)
    assert.equal(readFileSync(join(d, ...long.split('/')), 'utf8'), '#!java')
    assert.throws(() => extractTarGz(makeTarGz([{ name: '../../escape', data: 'x' }]), d), /Unsafe path/)
  })

  console.log('downloads')
  const { downloadVerified } = await import('../../src/main/tools/download')
  const payload = Buffer.from('tool-binary-contents')
  const good = createHash('sha256').update(payload).digest('hex')
  const realFetch = globalThis.fetch
  globalThis.fetch = (async () => new Response(payload, { headers: { 'content-length': String(payload.length) } })) as typeof fetch
  await t('accepts a matching checksum', async () => {
    assert.deepEqual(await downloadVerified('https://example.test/x', good, { maxBytes: 1000 }), payload)
  })
  await t('rejects a checksum mismatch, a missing checksum and oversized files', async () => {
    await assert.rejects(downloadVerified('https://example.test/x', 'a'.repeat(64), { maxBytes: 1000 }), /Checksum mismatch/)
    await assert.rejects(downloadVerified('https://example.test/x', '', { maxBytes: 1000 }), /checksum/i)
    await assert.rejects(downloadVerified('https://example.test/x', good, { maxBytes: 5 }), /larger than expected|exceeded/)
  })
  globalThis.fetch = realFetch

  console.log('tool manager')
  const m = await import('../../src/main/tools/manager')
  await t('parses Java versions old and new', () => {
    assert.equal(m.parseJavaVersion('java version "1.8.0_481"'), 8)
    assert.equal(m.parseJavaVersion('openjdk version "21.0.5" 2024-10-15 LTS'), 21)
    assert.equal(m.parseJavaVersion('openjdk version "25" 2025-09-16'), 25)
    assert.equal(m.parseJavaVersion('nonsense'), null)
  })
  await t('picks the right Nuclei asset per platform', () => {
    assert.equal(m.nucleiAssetSuffix('win32', 'x64'), '_windows_amd64.zip')
    assert.equal(m.nucleiAssetSuffix('darwin', 'arm64'), '_macOS_arm64.zip')
    assert.equal(m.nucleiAssetSuffix('linux', 'x64'), '_linux_amd64.zip')
  })
  await t('parses release checksum files', () => {
    const sums = m.parseChecksums(`${'a'.repeat(64)}  nuclei_3.5.0_windows_amd64.zip\n${'b'.repeat(64)} *nuclei_3.5.0_linux_amd64.zip\njunk line`)
    assert.equal(sums.get('nuclei_3.5.0_windows_amd64.zip'), 'a'.repeat(64))
    assert.equal(sums.get('nuclei_3.5.0_linux_amd64.zip'), 'b'.repeat(64))
    assert.equal(sums.size, 2)
  })
  await t('clamps scanner settings', () => {
    m.saveSettings({ nucleiRate: 9999, nucleiMaxMinutes: 0, nucleiInteractsh: 'yes' as unknown as boolean, zapSpiderMinutes: 2.6, zapMaxMinutes: NaN })
    const s = m.settings()
    assert.equal(s.nucleiRate, 150); assert.equal(s.nucleiMaxMinutes, 2); assert.equal(s.nucleiInteractsh, false)
    assert.equal(s.zapSpiderMinutes, 3); assert.equal(s.zapMaxMinutes, 15)
  })
  await t('detects the ZAP install on this machine (if present)', () => {
    const z = m.zapInfo()
    if (existsSync('C:\\Program Files\\ZAP\\Zed Attack Proxy')) {
      assert.ok(z.found); assert.match(z.version!, /^\d+\.\d+\.\d+$/)
      assert.equal(z.version, '2.17.0', 'should prefer the newest jar when several are present')
    }
  })

  console.log('nuclei')
  const n = await import('../../src/main/scanners/nuclei')
  await t('never runs intrusive templates; interactsh off by default', () => {
    const args = n.nucleiArgs('mysite.com', { ...m.DEFAULT_SETTINGS })
    const etags = args[args.indexOf('-etags') + 1].split(',')
    for (const tag of ['dos', 'fuzz', 'intrusive', 'bruteforce']) assert.ok(etags.includes(tag), tag)
    assert.ok(args.includes('-ni')); assert.equal(args[args.indexOf('-u') + 1], 'https://mysite.com')
    assert.equal(args[args.indexOf('-rl') + 1], '20')
    assert.ok(!n.nucleiArgs('mysite.com', { ...m.DEFAULT_SETTINGS, nucleiInteractsh: true }).includes('-ni'))
  })
  await t('parses JSONL, merges repeats, keeps remediation and https references', () => {
    const line = (o: object) => JSON.stringify(o)
    const out = n.parseNucleiOutput(
      [
        '[INF] noise',
        line({ 'template-id': 'git-config', info: { name: 'Git Config Exposure', severity: 'medium', description: 'Git config is exposed.', remediation: 'Block /.git', reference: ['https://a.example/x', 'http://insecure.example'] }, 'matched-at': 'https://mysite.com/.git/config' }),
        line({ 'template-id': 'git-config', info: { name: 'Git Config Exposure', severity: 'medium' }, 'matched-at': 'https://www.mysite.com/.git/config' }),
        line({ 'template-id': 'CVE-2021-1234', info: { name: 'Old plugin RCE', severity: 'critical', classification: { 'cve-id': ['cve-2021-1234'] } }, 'matched-at': 'https://mysite.com/wp-content/x', 'extracted-results': ['1.2.3'] }),
        '{broken json'
      ].join('\n')
    )
    assert.equal(out.length, 2)
    const git = out.find((f) => f.checkId === 'nuclei.git-config')!
    assert.equal(git.severity, 'medium'); assert.equal(git.remediation, 'Block /.git'); assert.deepEqual(git.references, ['https://a.example/x'])
    assert.equal(git.evidence!.split('\n').length, 2); assert.equal(git.source, 'nuclei')
    const cve = out.find((f) => f.severity === 'critical')!
    assert.match(cve.title, /CVE-2021-1234/); assert.match(cve.evidence!, /1\.2\.3/)
  })

  console.log('zap')
  const z = await import('../../src/main/scanners/zap')
  await t('baseline plan is spider + passive only, scoped to the host', () => {
    const plan = JSON.parse(z.zapPlan('my-site.com', 'C:\\tmp\\r', 3))
    const types = plan.jobs.map((j: { type: string }) => j.type)
    assert.deepEqual(types, ['passiveScan-config', 'spider', 'passiveScan-wait', 'report'])
    assert.ok(!types.some((t: string) => /activeScan|ajax|openapi/i.test(t)))
    const re = new RegExp('^' + plan.env.contexts[0].includePaths[0] + '$')
    assert.ok(re.test('https://my-site.com/a?b=1')); assert.ok(re.test('https://www.my-site.com/'))
    assert.ok(!re.test('https://my-site.com.evil.test/')); assert.ok(!re.test('https://myXsite.com/'))
  })
  await t('parses the ZAP JSON report, skips false positives and duplicate header rules', () => {
    const report = JSON.stringify({
      site: [
        {
          '@name': 'https://mysite.com',
          alerts: [
            { pluginid: '10098', alertRef: '10098', alert: 'Cross-Domain Misconfiguration', riskcode: '2', confidence: '2', desc: '<p>CORS allows <b>any</b> origin &amp; more.</p>', solution: '<p>Restrict Access-Control-Allow-Origin.</p>', reference: '<p>https://cheatsheetseries.owasp.org/x</p>', count: '3', instances: [{ uri: 'https://mysite.com/api', method: 'GET', evidence: 'Access-Control-Allow-Origin: *' }] },
            { pluginid: '10038', alert: 'Content Security Policy (CSP) Header Not Set', riskcode: '2', confidence: '3' },
            { pluginid: '10027', alert: 'Information Disclosure - Suspicious Comments', riskcode: '0', confidence: '0' }
          ]
        }
      ]
    })
    const out = z.parseZapReport(report)
    assert.equal(out.length, 1)
    const f = out[0]
    assert.equal(f.severity, 'medium'); assert.match(f.title, /3 places/)
    assert.equal(f.detail, 'CORS allows any origin & more.'); assert.equal(f.remediation, 'Restrict Access-Control-Allow-Origin.')
    assert.deepEqual(f.references, ['https://cheatsheetseries.owasp.org/x']); assert.match(f.evidence!, /GET https:\/\/mysite.com\/api/)
  })

  console.log(`\n${passed} passed${process.exitCode ? ', some FAILED' : ''}`)
}
void main()
