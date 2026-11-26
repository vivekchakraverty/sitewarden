import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, existsSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { fakeD1 } from './fake-d1'

let passed = 0
async function t(name: string, fn: () => Promise<void> | void) {
  try { await fn(); passed++; console.log('  ok  ', name) } catch (e) { console.log('  FAIL', name, '\n', e); process.exitCode = 1 }
}

process.env.SW_TEST_DIR = mkdtempSync(join(tmpdir(), 'sw-'))
// timingSafeEqual exists in Workers, not in Node's WebCrypto
;(crypto.subtle as any).timingSafeEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i])

async function main() {
  // ---------- SQLite store + JSON migration ----------
  console.log('store')
  writeFileSync(join(process.env.SW_TEST_DIR!, 'sitewarden-data.json'), JSON.stringify({
    domains: [{ id: 'd1', host: 'mysite.com', addedAt: '2026-01-01T00:00:00Z', verificationToken: 'tok', verified: true, verifiedAt: new Date().toISOString(), verifiedBy: 'dns' }],
    scans: [{ id: 's1', domainId: 'd1', host: 'mysite.com', startedAt: '2026-01-02T00:00:00Z', finishedAt: '2026-01-02T00:00:05Z', score: 80, grade: 'B', findings: [{ checkId: 'x', severity: 'low', title: 'T', detail: 'D' }], checks: [] }]
  }))
  const { store } = await import('../../src/main/store')
  await t('migrates phase-1 JSON into SQLite', () => {
    assert.equal(store.domains().length, 1)
    assert.equal(store.domain('d1')!.verified, true)
    assert.equal(store.scans('d1')[0].findings[0].title, 'T')
    assert.ok(existsSync(join(process.env.SW_TEST_DIR!, 'sitewarden-data.json.migrated')))
  })
  await t('keeps only the newest 50 scans', () => {
    for (let i = 0; i < 55; i++) store.addScan({ ...store.scans('d1')[0], id: 'n' + i, startedAt: new Date(2026, 1, 1, 0, i).toISOString() })
    assert.equal(store.scans('d1').length, 50)
  })
  await t('kv and change log round-trip', () => {
    store.set('cf', { a: 1 }); assert.deepEqual(store.get('cf'), { a: 1 })
    const id = store.addChange({ domainId: 'd1', zoneId: 'z', item: 'min_tls', label: 'L', previous: '"1.0"', applied: '"1.2"', appliedAt: 'now' })
    assert.equal(store.change(id)!.previous, '"1.0"'); store.markReverted(id); assert.ok(store.change(id)!.revertedAt)
  })

  // ---------- Agent Worker ----------
  console.log('agent worker')
  const { buildWorkerSource } = await import('../../src/main/cloudflare/deploy')
  const src = buildWorkerSource()
  const modPath = join(process.env.SW_TEST_DIR!, 'agent.mjs'); writeFileSync(modPath, src)
  const worker = (await import('file://' + modPath.replace(/\\/g, '/'))).default
  const DB = fakeD1()
  const env = { DB, AGENT_TOKEN: 'secret-token', SITES: JSON.stringify(['mysite.com']), GUARD_SAMPLE: '0.5' }
  const ctx = { waitUntil: (p: Promise<unknown>) => p }
  const call = (path: string, init: RequestInit = {}) => worker.fetch(new Request('https://agent.example.workers.dev' + path, init), env, ctx)
  const auth = { Authorization: 'Bearer secret-token' }

  await t('serves guard.js with the sample rate baked in', async () => {
    const r = await call('/guard.js'); const js = await r.text()
    assert.equal(r.status, 200); assert.ok(js.includes('Math.random() >= 0.5')); assert.ok(!js.includes('__SAMPLE__'))
    new Function(js) // parses
  })
  await t('API rejects missing or wrong token', async () => {
    assert.equal((await call('/api/ping')).status, 401)
    assert.equal((await call('/api/ping', { headers: { Authorization: 'Bearer nope' } })).status, 401)
    assert.equal((await (await call('/api/ping', { headers: auth })).json()).ok, true)
  })

  const realFetch = globalThis.fetch
  let html = '<html><script src="https://cdn.jsdelivr.net/npm/a@1/a.js"></script><script src="/local.js"></script></html>'
  globalThis.fetch = (async (input: any) => {
    const u = String(input instanceof Request ? input.url : input)
    if (u.startsWith('https://mysite.com/')) return new Response(html, { headers: { 'content-type': 'text/html' } })
    throw new Error('unexpected fetch ' + u)
  }) as typeof fetch
  await t('first cron run baselines scripts without alerting', async () => {
    await worker.scheduled({}, env, ctx)
    const s = await (await call('/api/summary?site=mysite.com', { headers: auth })).json()
    assert.equal(s.checks.length, 1); assert.equal(s.checks[0].ok, true)
    assert.deepEqual(s.origins.map((o: any) => o.origin), ['https://cdn.jsdelivr.net/npm/a@1/a.js'])
    assert.equal(s.alerts.length, 0)
  })
  await t('a new third-party script raises an alert', async () => {
    html += '<script src="https://evil.example/skim.js"></script>'
    await worker.scheduled({}, env, ctx)
    const s = await (await call('/api/summary?site=mysite.com', { headers: auth })).json()
    assert.equal(s.alerts.length, 1); assert.equal(s.alerts[0].kind, 'new_script'); assert.ok(s.alerts[0].message.includes('evil.example'))
  })
  await t('two failed checks raise one down alert, recovery raises recovered', async () => {
    globalThis.fetch = (async () => { throw new Error('connect timeout') }) as typeof fetch
    await worker.scheduled({}, env, ctx); await worker.scheduled({}, env, ctx); await worker.scheduled({}, env, ctx)
    let s = await (await call('/api/summary?site=mysite.com', { headers: auth })).json()
    assert.equal(s.alerts.filter((a: any) => a.kind === 'down').length, 1)
    globalThis.fetch = (async () => new Response(html, { headers: { 'content-type': 'text/html' } })) as typeof fetch
    await worker.scheduled({}, env, ctx)
    s = await (await call('/api/summary?site=mysite.com', { headers: auth })).json()
    assert.equal(s.alerts[0].kind, 'recovered')
  })
  globalThis.fetch = realFetch

  await t('guard reports from the right origin are stored; others ignored', async () => {
    const body = JSON.stringify({ page: '/checkout', scripts: ['https://mysite.com/app.js', 'https://new-tag.example/t.js'], inline: 2, violations: [{ d: 'script-src', b: 'https://x.example/a.js' }] })
    await call('/r/guard?site=mysite.com', { method: 'POST', body, headers: { origin: 'https://attacker.example' } })
    let s = await (await call('/api/summary?site=mysite.com', { headers: auth })).json()
    assert.ok(!s.origins.some((o: any) => o.origin.includes('new-tag')))
    const r = await call('/r/guard?site=mysite.com', { method: 'POST', body, headers: { origin: 'https://www.mysite.com' } })
    assert.equal(r.status, 204)
    s = await (await call('/api/summary?site=mysite.com', { headers: auth })).json()
    assert.ok(s.origins.some((o: any) => o.origin === 'https://new-tag.example/t.js' && o.source === 'browser'))
    assert.ok(!s.origins.some((o: any) => o.origin.includes('mysite.com')))
    assert.ok(s.csp.some((c: any) => c.directive === 'script-src'))
  })
  await t('CSP reports (both formats) aggregate; foreign documents ignored', async () => {
    const one = JSON.stringify({ 'csp-report': { 'document-uri': 'https://mysite.com/a', 'effective-directive': 'script-src-elem', 'blocked-uri': 'https://cdn.bad/x.js?q=1' } })
    await call('/r/csp?site=mysite.com', { method: 'POST', body: one })
    await call('/r/csp?site=mysite.com', { method: 'POST', body: one })
    await call('/r/csp', { method: 'POST', body: JSON.stringify([{ type: 'csp-violation', body: { documentURL: 'https://mysite.com/b', effectiveDirective: 'script-src-elem', blockedURL: 'https://cdn.bad/x.js' } }]) })
    await call('/r/csp', { method: 'POST', body: JSON.stringify({ 'csp-report': { 'document-uri': 'https://other.com/', 'effective-directive': 'img-src', 'blocked-uri': 'https://z' } }) })
    const s = await (await call('/api/summary?site=mysite.com', { headers: auth })).json()
    const row = s.csp.find((c: any) => c.blocked === 'https://cdn.bad/x.js')
    assert.equal(row.count, 3); assert.ok(!s.csp.some((c: any) => c.directive === 'img-src'))
  })
  await t('approve and ack update state', async () => {
    await call('/api/approve?site=mysite.com', { method: 'POST', headers: auth, body: JSON.stringify({ origin: 'https://evil.example/skim.js', approved: true }) })
    await call('/api/ack?site=mysite.com', { method: 'POST', headers: auth, body: '{}' })
    const s = await (await call('/api/summary?site=mysite.com', { headers: auth })).json()
    assert.ok(s.origins.find((o: any) => o.origin === 'https://evil.example/skim.js').approved)
    assert.ok(s.alerts.every((a: any) => a.acked))
  })
  await t('oversized report bodies are dropped', async () => {
    const r = await call('/r/csp', { method: 'POST', body: 'x'.repeat(70000) }); assert.equal(r.status, 204)
  })

  // ---------- Deploy + hardening against a mocked Cloudflare API ----------
  console.log('cloudflare client')
  const secrets = await import('../../src/main/secrets')
  secrets.setSecret('cloudflareToken', 'T'.repeat(40))
  secrets.setSecret('safeBrowsing', 'sb-key')
  const calls: { method: string; path: string; body?: any; form?: FormData }[] = []
  const rules: Record<string, any[]> = {}
  let siteCsp = ''
  let siteHtml = '<html></html>'
  const settings: Record<string, unknown> = { min_tls_version: '1.0', always_use_https: 'off' }
  globalThis.fetch = (async (input: any, init: RequestInit = {}) => {
    const url = new URL(String(input)); const method = init.method ?? 'GET'
    const path = url.pathname.replace('/client/v4', '')
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined
    calls.push({ method, path: path + url.search, body, form: init.body instanceof FormData ? init.body : undefined })
    const ok = (result: unknown) => new Response(JSON.stringify({ success: true, result, errors: [] }), { headers: { 'content-type': 'application/json' } })
    if (url.hostname.endsWith('workers.dev')) return new Response('{"ok":true}')
    if (url.hostname === 'mysite.com') {
      const override = rules['http_response_headers_transform']?.find((r) => r.ref === 'sitewarden_csp_allow_agent')
      const csp = override ? override.action_parameters.headers['Content-Security-Policy'].value : siteCsp
      return new Response(siteHtml, { headers: { 'content-type': 'text/html', ...(csp ? { 'content-security-policy': csp } : {}) } })
    }
    if (path === '/accounts') return ok([{ id: 'acc1', name: 'My account' }])
    if (path.endsWith('/d1/database') && method === 'GET') return ok([])
    if (path.endsWith('/d1/database') && method === 'POST') return ok({ uuid: 'db-uuid' })
    if (path.endsWith('/workers/subdomain')) return ok({ subdomain: 'me' })
    if (path.includes('/workers/scripts/')) return ok({})
    if (path === '/zones') return ok(url.searchParams.get('name') === 'mysite.com' ? [{ id: 'z1', name: 'mysite.com', plan: { name: 'Free Website' } }] : [])
    const sm = path.match(/^\/zones\/z1\/settings\/(\w+)$/)
    if (sm) { if (method === 'PATCH') settings[sm[1]] = body.value; return ok({ value: settings[sm[1]] ?? 'off' }) }
    if (path === '/zones/z1/bot_management') return ok({ fight_mode: false })
    const ep = path.match(/^\/zones\/z1\/rulesets\/phases\/(\w+)\/entrypoint$/)
    if (ep) {
      if (method === 'PUT') { rules[ep[1]] = body.rules.map((r: any, i: number) => ({ ...r, id: 'r' + i })); return ok({ id: 'rs-' + ep[1], rules: rules[ep[1]] }) }
      return rules[ep[1]] ? ok({ id: 'rs-' + ep[1], rules: rules[ep[1]] }) : new Response(JSON.stringify({ success: false, errors: [{ code: 10003, message: 'not found' }] }), { status: 404 })
    }
    const rr = path.match(/^\/zones\/z1\/rulesets\/rs-(\w+)\/rules(?:\/(\w+))?$/)
    if (rr) {
      const list = rules[rr[1]]
      if (method === 'POST') list.push({ ...body, id: 'r' + list.length })
      if (method === 'PATCH') Object.assign(list.find((r) => r.id === rr[2]), body)
      if (method === 'DELETE') rules[rr[1]] = list.filter((r) => r.id !== rr[2])
      return ok({ id: 'rs-' + rr[1], rules: rules[rr[1]] })
    }
    return new Response(JSON.stringify({ success: false, errors: [{ code: 7003, message: 'no route ' + method + ' ' + path }] }), { status: 400 })
  }) as typeof fetch

  const deploy = await import('../../src/main/cloudflare/deploy')
  await t('deploy uploads the worker with D1, secrets and only verified sites', async () => {
    const r = await deploy.deploy({ accountId: 'acc1', copyKeys: true, alertWebhook: 'https://hooks.example/x' })
    assert.equal(r.workerUrl, 'https://sitewarden-agent.me.workers.dev'); assert.deepEqual(r.sites, ['mysite.com'])
    const up = calls.find((c) => c.method === 'PUT' && c.path === '/accounts/acc1/workers/scripts/sitewarden-agent')!
    const meta = JSON.parse(await (up.form!.get('metadata') as Blob).text())
    assert.equal(meta.main_module, 'agent.js')
    const names = meta.bindings.map((b: any) => b.name).sort()
    assert.deepEqual(names, ['AGENT_TOKEN', 'ALERT_WEBHOOK', 'DB', 'GUARD_SAMPLE', 'SB_KEY', 'SITES'])
    assert.equal(meta.bindings.find((b: any) => b.name === 'DB').id, 'db-uuid')
    const code = await (up.form!.get('agent.js') as Blob).text(); assert.ok(!code.includes('__GUARD_SOURCE__'))
    assert.ok(calls.some((c) => c.path.endsWith('/schedules') && c.body[0].cron === '*/30 * * * *'))
  })
  const hard = await import('../../src/main/cloudflare/hardening')
  await t('hardening reads the zone and pre-selects only safe items', async () => {
    const h = await hard.hardening('d1')
    assert.equal(h.zoneName, 'mysite.com')
    const tls = h.items.find((i) => i.id === 'min_tls')!; assert.equal(tls.current, '1.0'); assert.equal(tls.done, false)
    assert.equal(h.items.find((i) => i.id === 'hsts')!.recommendedByDefault, false)
    assert.equal(h.items.find((i) => i.id === 'ssl_strict')!.recommendedByDefault, false)
  })
  await t('apply + revert restores previous values and leaves user rules alone', async () => {
    rules['http_response_headers_transform'] = [{ id: 'user1', ref: 'mine', expression: 'true', action: 'rewrite' }]
    const res = await hard.applyItems('d1', ['min_tls', 'security_headers', 'csp_report_only'])
    assert.ok(res.every((r) => r.ok), JSON.stringify(res))
    assert.equal(settings.min_tls_version, '1.2')
    const hdr = rules['http_response_headers_transform']
    assert.equal(hdr.length, 3); assert.ok(hdr.some((r) => r.ref === 'mine'))
    const csp = hdr.find((r) => r.ref === 'sitewarden_csp_report_only')
    assert.ok(csp.action_parameters.headers['Content-Security-Policy-Report-Only'].value.includes('https://sitewarden-agent.me.workers.dev/r/csp?site=mysite.com'))
    assert.ok(hdr.find((r) => r.ref === 'sitewarden_security_headers').expression.includes('"www.mysite.com"'))
    for (const c of store.changes('d1').filter((c) => !c.revertedAt)) assert.ok((await hard.revert(c.id)).ok)
    assert.equal(settings.min_tls_version, '1.0')
    assert.deepEqual(rules['http_response_headers_transform'].map((r) => r.ref), ['mine'])
  })
  await t('refuses hardening on unverified domains', async () => {
    store.upsertDomain({ ...store.domain('d1')!, id: 'd2', host: 'notmine.com', verified: false, verificationToken: 'x' })
    const h = await hard.hardening('d2'); assert.ok(h.error?.includes('Verify'))
  })
  // ---------- CSP helper ----------
  console.log('csp helper')
  const csp = await import('../../src/main/csp')
  const W = 'https://sitewarden-agent.me.workers.dev'
  await t('host sources, wildcards and keywords are matched like browsers do', () => {
    const u = new URL(W + '/guard.js')
    assert.ok(csp.sourcesAllow(['https:'], u)); assert.ok(csp.sourcesAllow(['*'], u))
    assert.ok(csp.sourcesAllow(['*.workers.dev'], u)); assert.ok(csp.sourcesAllow(['https://*.me.workers.dev'], u))
    assert.ok(!csp.sourcesAllow(["'self'", "'unsafe-inline'"], u)); assert.ok(!csp.sourcesAllow(['workers.dev'], u))
    assert.ok(!csp.sourcesAllow(['sitewarden-agent.me.workers.dev:8443'], u))
    assert.ok(csp.sourcesAllow(['sitewarden-agent.me.workers.dev/guard.js'], u)); assert.ok(!csp.sourcesAllow(['sitewarden-agent.me.workers.dev/other.js'], u))
  })
  await t('patches script-src and connect-src, keeping everything else', () => {
    const a = csp.analysePolicy("default-src 'self'; script-src 'self' https://cdn.x.com; img-src *", W)
    assert.equal(a.problems.length, 2)
    const p = csp.parsePolicy(a.patched)
    assert.deepEqual(p.get('script-src'), ["'self'", 'https://cdn.x.com', W])
    assert.deepEqual(p.get('connect-src'), ["'self'", W])
    assert.deepEqual(p.get('default-src'), ["'self'"]); assert.deepEqual(p.get('img-src'), ['*'])
    assert.equal(csp.analysePolicy(a.patched, W).problems.length, 0)
  })
  await t("patches script-src-elem when present and drops 'none'", () => {
    const a = csp.analysePolicy("default-src 'none'; script-src-elem 'self'; connect-src 'none'", W)
    const p = csp.parsePolicy(a.patched)
    assert.deepEqual(p.get('script-src-elem'), ["'self'", W]); assert.deepEqual(p.get('connect-src'), [W]); assert.equal(p.get('script-src'), undefined)
  })
  await t("flags 'strict-dynamic' and nonces", () => {
    const a = csp.analysePolicy("script-src 'nonce-abc' 'strict-dynamic'; connect-src 'self'", W)
    assert.ok(a.strictDynamic && a.hasNonce); assert.ok(a.problems.some((x) => x.includes('strict-dynamic')))
  })
  await t('checkCsp: no policy, header policy, meta policy, nonce', async () => {
    siteCsp = ''; siteHtml = '<html></html>'
    assert.equal((await csp.checkCsp('mysite.com', W, true)).status, 'none')
    siteCsp = "default-src 'self'"
    let r = await csp.checkCsp('mysite.com', W, true)
    assert.equal(r.status, 'blocked'); assert.ok(r.canAutoFix); assert.ok(r.headerPatched!.includes(W))
    siteCsp = ''; siteHtml = `<html><head><meta http-equiv="Content-Security-Policy" content="script-src 'self'"></head></html>`
    r = await csp.checkCsp('mysite.com', W, true)
    assert.equal(r.status, 'blocked'); assert.ok(!r.canAutoFix); assert.ok(r.metaPatched!.includes(W)); assert.match(r.autoFixNote!, /meta/)
    siteHtml = '<html></html>'; siteCsp = "script-src 'self' 'nonce-r4nd0m'"
    r = await csp.checkCsp('mysite.com', W, true)
    assert.equal(r.status, 'blocked'); assert.ok(!r.canAutoFix); assert.match(r.autoFixNote!, /nonce/)
    assert.ok(!(await csp.checkCsp('mysite.com', W, false)).canAutoFix)
  })
  await t('one-click Cloudflare fix overrides the header and can be reverted', async () => {
    siteCsp = "default-src 'self'; script-src 'self'"
    const { result, check } = await hard.applyCspFix('d1')
    assert.ok(result.ok, result.message); assert.equal(check.status, 'allowed')
    const ch = store.changes('d1').find((c) => c.item === 'csp_allow_agent' && !c.revertedAt)!
    assert.ok((await hard.revert(ch.id)).ok)
    assert.equal((await csp.checkCsp('mysite.com', W, true)).status, 'blocked')
    assert.ok(!(await hard.hardening('d1')).items.some((i) => i.id === 'csp_allow_agent'))
    assert.equal((await hard.applyItems('d1', ['csp_allow_agent']))[0].ok, false)
  })

  globalThis.fetch = realFetch
  console.log(`\n${passed} passed${process.exitCode ? ', some FAILED' : ''}`)
}
void main()
