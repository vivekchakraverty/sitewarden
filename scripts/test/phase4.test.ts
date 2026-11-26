import assert from 'node:assert/strict'
import { execFileSync, spawn, spawnSync } from 'child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { createServer } from 'http'
import { tmpdir } from 'os'
import { join, resolve } from 'path'
import { fakeD1 } from './fake-d1'

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

process.env.SW_TEST_DIR = mkdtempSync(join(tmpdir(), 'sw4-'))
;(crypto.subtle as any).timingSafeEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i])
const PY = process.platform === 'win32' ? 'python' : 'python3'

async function main() {
  const { buildWorkerSource } = await import('../../src/main/cloudflare/deploy')
  const modPath = join(process.env.SW_TEST_DIR!, 'agent.mjs')
  writeFileSync(modPath, buildWorkerSource())
  const worker = (await import('file://' + modPath.replace(/\\/g, '/'))).default
  const env = { DB: fakeD1(), AGENT_TOKEN: 'desk-token', VM_TOKEN: 'vm-token-0123456789abcdef', SITES: JSON.stringify(['mysite.com']), GUARD_SAMPLE: '0.1' }
  const ctx = { waitUntil: (p: Promise<unknown>) => p }
  const call = (path: string, token: string, init: RequestInit = {}) =>
    worker.fetch(new Request('https://agent.test' + path, { ...init, headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) } }), env, ctx)
  const DESK = 'desk-token'
  const VM = env.VM_TOKEN

  console.log('worker vm mailbox')
  await t('tokens are separated: VM cannot read desktop data, desktop cannot post as VM', async () => {
    assert.equal((await call('/api/summary?site=mysite.com', VM)).status, 401)
    assert.equal((await call('/api/vm/status', VM)).status, 401)
    assert.equal((await call('/api/vm/results', VM)).status, 401)
    assert.equal((await call('/api/vm/result', DESK, { method: 'POST', body: '{}' })).status, 401)
    assert.equal((await call('/api/vm/config', DESK)).status, 401)
    assert.equal((await call('/api/vm/config', 'nope')).status, 401)
  })
  await t('config returns verified sites, default schedule and queued jobs (deduplicated)', async () => {
    let c = await (await call('/api/vm/config', VM)).json()
    assert.deepEqual(c.sites, ['mysite.com']); assert.equal(c.settings.intervalHours, 24); assert.deepEqual(c.jobs, [])
    assert.equal((await (await call('/api/vm/scan?site=mysite.com', DESK, { method: 'POST', body: '{}' })).json()).alreadyQueued, false)
    assert.equal((await (await call('/api/vm/scan?site=mysite.com', DESK, { method: 'POST', body: '{}' })).json()).alreadyQueued, true)
    assert.equal((await call('/api/vm/scan?site=evil.com', DESK, { method: 'POST', body: '{}' })).status, 404)
    c = await (await call('/api/vm/config', VM)).json()
    assert.equal(c.jobs.length, 1); assert.equal(c.jobs[0].site, 'mysite.com')
  })
  await t('settings are clamped before the VM sees them', async () => {
    await call('/api/vm/settings', DESK, { method: 'POST', body: JSON.stringify({ intervalHours: 0, nucleiRate: 9999, nucleiInteractsh: 'yes', enabled: false }) })
    const c = await (await call('/api/vm/config', VM)).json()
    assert.equal(c.settings.intervalHours, 1); assert.equal(c.settings.nucleiRate, 150); assert.equal(c.settings.nucleiInteractsh, false); assert.equal(c.settings.enabled, false)
    await call('/api/vm/settings', DESK, { method: 'POST', body: JSON.stringify({ intervalHours: 24, enabled: true }) })
  })
  await t('results for unknown sites or oversized bodies are rejected', async () => {
    assert.equal((await call('/api/vm/result', VM, { method: 'POST', body: JSON.stringify({ site: 'other.com', nuclei: '', zap: '' }) })).status, 400)
    assert.equal((await call('/api/vm/result', VM, { method: 'POST', body: 'x'.repeat(3_400_000) })).status, 400)
  })

  // ---------- full chain: python agent -> worker -> desktop import ----------
  console.log('python agent end-to-end (fake docker)')
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(c as Buffer)
    const body = chunks.length ? Buffer.concat(chunks) : undefined
    const r: Response = await worker.fetch(
      new Request('https://agent.test' + req.url, { method: req.method, headers: req.headers as Record<string, string>, body: req.method === 'GET' ? undefined : body }),
      env,
      ctx
    )
    res.writeHead(r.status, Object.fromEntries(r.headers))
    res.end(Buffer.from(await r.arrayBuffer()))
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as { port: number }).port
  const base = `http://127.0.0.1:${port}`

  const dir = mkdtempSync(join(tmpdir(), 'sw-vm-'))
  const conf = join(dir, 'agent.json')
  writeFileSync(conf, JSON.stringify({ worker: base, token: VM }))
  const dockerLog = join(dir, 'docker.log')
  const agentPath = resolve('src/oracle/agent.py')
  // Async spawn: the Worker is served from this process, so blocking here would deadlock it.
  const runAgent = (): Promise<{ status: number | null; stdout: string; stderr: string }> =>
    new Promise((done) => {
      const p = spawn(PY, [agentPath], {
        env: { ...process.env, SITEWARDEN_CONF: conf, SITEWARDEN_STATE: join(dir, 'state'), SITEWARDEN_DOCKER_CMD: JSON.stringify([PY, resolve('scripts/test/fake_docker.py')]), FAKE_DOCKER_LOG: dockerLog }
      })
      let stdout = ''
      let stderr = ''
      p.stdout.on('data', (c) => (stdout += c))
      p.stderr.on('data', (c) => (stderr += c))
      const timer = setTimeout(() => p.kill(), 60000)
      p.on('close', (status) => {
        clearTimeout(timer)
        done({ status, stdout, stderr })
      })
    })

  await t('agent.py compiles', () => {
    execFileSync(PY, ['-c', `import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())`, agentPath])
  })
  await t('first run: updates images, scans the queued site, uploads results, alerts on high issues', async () => {
    const r = await runAgent()
    assert.equal(r.status, 0, r.stdout + r.stderr)
    assert.match(r.stdout, /scanning mysite\.com \(requested\)/)
    const calls = readFileSync(dockerLog, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as string[])
    assert.ok(calls.some((c) => c[0] === 'pull' && c.includes('zaproxy/zap-stable')))
    const scan = calls.find((c) => c.includes('-u'))!
    assert.equal(scan[scan.indexOf('-u') + 1], 'https://mysite.com')
    assert.ok(scan.includes('-ni') && scan.includes('-or') && scan.includes('--network'))
    for (const tag of ['dos', 'intrusive', 'bruteforce']) assert.ok(scan[scan.indexOf('-etags') + 1].split(',').includes(tag))
    const st = await (await call('/api/vm/status', DESK)).json()
    assert.equal(st.jobs.length, 0, 'job marked done'); assert.equal(st.latest[0].high, 2) // nuclei high + zap high
    assert.equal(st.heartbeat.state, 'idle'); assert.equal(st.heartbeat.agentVersion, '0.4.0')
    const s = await (await call('/api/summary?site=mysite.com', DESK)).json()
    assert.ok(s.alerts.some((a: any) => a.kind === 'deep_scan' && a.message.includes('2 high')))
  })
  await t('second run: nothing due, no new scan, images not re-pulled', async () => {
    const before = readFileSync(dockerLog, 'utf8').trim().split('\n').length
    const r = await runAgent()
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /nothing due/)
    assert.equal(readFileSync(dockerLog, 'utf8').trim().split('\n').length, before)
  })
  await t('rejected token tells the user how to fix it', async () => {
    writeFileSync(conf, JSON.stringify({ worker: base, token: 'wrong-token-xxxxxxxxxxxx' }))
    const r = await runAgent()
    assert.equal(r.status, 1); assert.match(r.stdout, /set-token/)
    writeFileSync(conf, JSON.stringify({ worker: base, token: VM }))
  })
  await t('set-token validates and saves', () => {
    const env2 = { ...process.env, SITEWARDEN_CONF: conf }
    assert.equal(spawnSync(PY, [agentPath, 'set-token', 'bad'], { env: env2 }).status, 2)
    assert.equal(spawnSync(PY, [agentPath, 'set-token', VM], { env: env2 }).status, 0)
    assert.equal(JSON.parse(readFileSync(conf, 'utf8')).token, VM)
  })

  console.log('desktop import')
  const { store } = await import('../../src/main/store')
  const secrets = await import('../../src/main/secrets')
  store.upsertDomain({ id: 'd1', host: 'mysite.com', addedAt: 'x', verificationToken: 't', verified: true, verifiedAt: new Date().toISOString(), verifiedBy: 'dns' })
  store.set('cf', { accountId: 'acc', workerUrl: base, sites: ['mysite.com'], keysCopied: false })
  secrets.setSecret('agentToken', DESK)
  secrets.setSecret('vmToken', VM)
  const vm = await import('../../src/main/oracle/vm')
  await t('imports VM results into scan history with parsed findings, once', async () => {
    assert.equal(await vm.importResults(), 1)
    assert.equal(await vm.importResults(), 0)
    const scan = store.scans('d1')[0]
    assert.equal(scan.origin, 'oracle'); assert.equal(scan.grade, 'D')
    assert.deepEqual(scan.findings.map((f) => f.severity), ['high', 'high', 'medium', 'medium'])
    assert.ok(scan.findings.some((f) => f.source === 'zap' && f.remediation === 'Restrict it'))
    assert.deepEqual(scan.checks.map((c) => c.status), ['issues', 'issues'])
  })
  await t('status reflects the VM; queueing a scan for an unverified domain is refused', async () => {
    const s = await vm.status()
    assert.ok(s.available && s.tokenCreated && !s.needsRedeploy); assert.equal(s.heartbeat?.hostname?.length ? true : false, true)
    store.upsertDomain({ id: 'd2', host: 'notmine.com', addedAt: 'x', verificationToken: 't', verified: false })
    await assert.rejects(vm.scanNow('d2'), /Verify/)
    assert.equal((await vm.scanNow('d1')).alreadyQueued, false)
  })
  await t('cloud-init embeds the agent, config and timer correctly', () => {
    const ci = vm.buildCloudInit('https://sitewarden-agent.me.workers.dev', 'tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    assert.ok(ci.startsWith('#cloud-config\n'))
    const blobs = [...ci.matchAll(/content: ([A-Za-z0-9+/=]{20,})$/gm)].map((m) => Buffer.from(m[1], 'base64').toString('utf8'))
    assert.deepEqual(JSON.parse(blobs[0]), { worker: 'https://sitewarden-agent.me.workers.dev', token: 'tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ' })
    assert.equal(blobs[1], readFileSync(agentPath, 'utf8'))
    assert.match(ci, /OnUnitInactiveSec=10min/); assert.match(ci, /enable, --now, sitewarden-agent\.timer/)
    assert.match(ci, /path: \/etc\/sitewarden\/agent\.json\n    permissions: '0600'/)
    // every block-literal line under write_files is indented deeper than its key
    for (const block of ci.split('    content: |\n').slice(1)) {
      const lines = block.split('\n')
      for (const l of lines.slice(0, lines.findIndex((x) => /^ {2}- |^runcmd:/.test(x)))) if (l) assert.ok(l.startsWith('      '), JSON.stringify(l))
    }
  })
  server.close()
  console.log(`\n${passed} passed${process.exitCode ? ', some FAILED' : ''}`)
}
void main()
