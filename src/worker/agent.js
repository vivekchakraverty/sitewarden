// SiteWarden agent: deployed by the desktop app into the user's own Cloudflare account.
// - every 30 min: uptime, new third-party scripts in the HTML, Safe Browsing / URLhaus
// - /guard.js + /r/guard: browser-side script inventory from real page views
// - /r/csp: CSP violation reports (report-uri and Reporting API formats)
// - /api/*: read by the desktop app with the AGENT_TOKEN bearer token
// - /api/vm/*: mailbox for the optional Oracle VM scan agent (VM_TOKEN can only read config and post results)
// Env: DB (D1), AGENT_TOKEN, SITES (JSON array), GUARD_SAMPLE, SB_KEY?, URLHAUS_KEY?, ALERT_WEBHOOK?, VM_TOKEN?

const VERSION = '0.4.0'
const GUARD_SOURCE = __GUARD_SOURCE__
const MAX_BODY = 64 * 1024
const MAX_VM_BODY = 3.2 * 1024 * 1024
const MAX_VM_FIELD = 1_500_000
const VM_DEFAULTS = { enabled: true, intervalHours: 24, nucleiRate: 20, nucleiMaxMinutes: 30, nucleiInteractsh: false, zapSpiderMinutes: 3, zapMaxMinutes: 15 }
const MAX_ORIGINS_PER_SITE = 500
const UA = 'SiteWarden-Agent/0.2 (owner-installed monitor)'

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS checks (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, ts TEXT NOT NULL,
     ok INTEGER NOT NULL, status INTEGER NOT NULL, ms INTEGER NOT NULL, error TEXT)`,
  `CREATE INDEX IF NOT EXISTS checks_site_ts ON checks(site, ts)`,
  `CREATE TABLE IF NOT EXISTS script_origins (site TEXT NOT NULL, origin TEXT NOT NULL, source TEXT NOT NULL,
     first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 1, approved INTEGER NOT NULL DEFAULT 0,
     PRIMARY KEY (site, origin))`,
  `CREATE TABLE IF NOT EXISTS csp_reports (site TEXT NOT NULL, directive TEXT NOT NULL, blocked TEXT NOT NULL,
     first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1, sample TEXT,
     PRIMARY KEY (site, directive, blocked))`,
  `CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, ts TEXT NOT NULL,
     kind TEXT NOT NULL, message TEXT NOT NULL, acked INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS vm_results (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, started_at TEXT NOT NULL,
     finished_at TEXT NOT NULL, received_at TEXT NOT NULL, nuclei TEXT NOT NULL, zap TEXT NOT NULL, errors TEXT NOT NULL,
     agent_version TEXT, high INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS vm_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, requested_at TEXT NOT NULL, done_at TEXT)`
]

let schemaReady = false
async function ensureSchema(env) {
  if (schemaReady) return
  await env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s)))
  schemaReady = true
}

function sites(env) {
  try {
    return JSON.parse(env.SITES || '[]')
  } catch {
    return []
  }
}

/** Maps a hostname (possibly www.) to a configured site, or null. */
function siteFor(env, host) {
  if (!host) return null
  host = String(host).toLowerCase()
  for (const s of sites(env)) {
    if (host === s || host === 'www.' + s || 'www.' + host === s) return s
  }
  return null
}

const now = () => new Date().toISOString()
const clip = (s, n = 500) => String(s ?? '').slice(0, n)

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...extra } })
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400'
}

async function readBody(request, max = MAX_BODY) {
  const len = Number(request.headers.get('content-length') || 0)
  if (len > max) return null
  const text = await request.text()
  if (text.length > max) return null
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function timingSafeEqual(a, b) {
  const enc = new TextEncoder()
  const x = enc.encode(a)
  const y = enc.encode(b)
  if (x.byteLength !== y.byteLength) return false
  return crypto.subtle.timingSafeEqual(x, y)
}

function bearerMatches(request, secret) {
  const h = request.headers.get('authorization') || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : ''
  return Boolean(secret) && Boolean(token) && timingSafeEqual(token, secret)
}
const authorized = (request, env) => bearerMatches(request, env.AGENT_TOKEN)

async function getState(env, k) {
  const r = await env.DB.prepare('SELECT v FROM state WHERE k = ?').bind(k).first()
  return r ? r.v : null
}
async function setState(env, k, v) {
  if (v === null) await env.DB.prepare('DELETE FROM state WHERE k = ?').bind(k).run()
  else await env.DB.prepare('INSERT INTO state (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind(k, String(v)).run()
}

async function alert(env, ctx, site, kind, message) {
  await env.DB.prepare('INSERT INTO alerts (site, ts, kind, message) VALUES (?, ?, ?, ?)').bind(site, now(), kind, clip(message, 1000)).run()
  if (env.ALERT_WEBHOOK) {
    const text = `SiteWarden [${site}] ${message}`
    const p = fetch(env.ALERT_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, content: text })
    }).catch(() => undefined)
    if (ctx) ctx.waitUntil(p)
    else await p
  }
}

/** Upserts script origins; returns the ones never seen before. */
async function recordOrigins(env, site, list, source) {
  const ts = now()
  const existing = new Set(
    (await env.DB.prepare('SELECT origin FROM script_origins WHERE site = ?').bind(site).all()).results.map((r) => r.origin)
  )
  const fresh = []
  const stmts = []
  for (const raw of list) {
    const origin = clip(raw, 300)
    if (!/^https?:\/\//.test(origin)) continue
    if (!existing.has(origin)) {
      if (existing.size + fresh.length >= MAX_ORIGINS_PER_SITE) continue
      fresh.push(origin)
    }
    stmts.push(
      env.DB.prepare(
        `INSERT INTO script_origins (site, origin, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(site, origin) DO UPDATE SET last_seen = excluded.last_seen, hits = hits + 1`
      ).bind(site, origin, source, ts, ts)
    )
  }
  if (stmts.length) await env.DB.batch(stmts)
  return { fresh, baseline: existing.size === 0 }
}

function sameSite(url, site) {
  try {
    const h = new URL(url).hostname
    return h === site || h.endsWith('.' + site)
  } catch {
    return false
  }
}

// ---------- browser reports ----------

async function handleGuard(request, env, ctx, url) {
  const site = siteFor(env, url.searchParams.get('site'))
  const origin = request.headers.get('origin')
  if (!site || !origin || siteFor(env, safeHost(origin)) !== site) return new Response(null, { status: 204, headers: CORS })
  const body = await readBody(request)
  if (!body || !Array.isArray(body.scripts)) return new Response(null, { status: 204, headers: CORS })

  const external = body.scripts.filter((s) => typeof s === 'string' && !sameSite(s, site)).slice(0, 100)
  const { fresh, baseline } = await recordOrigins(env, site, external, 'browser')
  if (fresh.length && !baseline) {
    await alert(env, ctx, site, 'new_script', `New third-party script seen in a visitor's browser: ${fresh.slice(0, 5).join(', ')}`)
  }
  if (Array.isArray(body.violations)) {
    const ts = now()
    const stmts = body.violations.slice(0, 20).map((v) =>
      env.DB.prepare(
        `INSERT INTO csp_reports (site, directive, blocked, first_seen, last_seen, sample) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(site, directive, blocked) DO UPDATE SET last_seen = excluded.last_seen, count = count + 1`
      ).bind(site, clip(v && v.d, 80), clip(v && v.b, 300), ts, ts, clip(body.page, 200))
    )
    if (stmts.length) await env.DB.batch(stmts)
  }
  return new Response(null, { status: 204, headers: CORS })
}

function safeHost(u) {
  try {
    return new URL(u).hostname
  } catch {
    return ''
  }
}

async function handleCsp(request, env, url) {
  const body = await readBody(request)
  if (!body) return new Response(null, { status: 204, headers: CORS })
  // report-uri: {"csp-report": {...}}; Reporting API: [{type: "csp-violation", body: {...}}]
  const reports = Array.isArray(body)
    ? body.filter((r) => r && r.type === 'csp-violation').map((r) => r.body || {})
    : body['csp-report']
      ? [body['csp-report']]
      : []
  const hinted = siteFor(env, url.searchParams.get('site'))
  const ts = now()
  const stmts = []
  for (const r of reports.slice(0, 20)) {
    const doc = r.documentURL || r['document-uri'] || ''
    const site = siteFor(env, safeHost(doc))
    if (!site || (hinted && hinted !== site)) continue
    const directive = clip(r.effectiveDirective || r['effective-directive'] || r['violated-directive'], 80)
    let blocked = clip(r.blockedURL || r['blocked-uri'] || '', 300)
    try {
      if (/^https?:/.test(blocked)) {
        const b = new URL(blocked)
        blocked = b.origin + b.pathname
      }
    } catch {
      // keep as-is ("inline", "eval", ...)
    }
    const sample = clip(r.sample || r['script-sample'] || '', 200)
    stmts.push(
      env.DB.prepare(
        `INSERT INTO csp_reports (site, directive, blocked, first_seen, last_seen, sample) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(site, directive, blocked) DO UPDATE SET last_seen = excluded.last_seen, count = count + 1`
      ).bind(site, directive, blocked, ts, ts, sample)
    )
  }
  if (stmts.length) await env.DB.batch(stmts)
  return new Response(null, { status: 204, headers: CORS })
}

// ---------- desktop API ----------

async function handleApi(request, env, url) {
  if (!authorized(request, env)) return json({ error: 'unauthorized' }, 401)
  const path = url.pathname
  if (path === '/api/ping') return json({ ok: true, version: VERSION, sites: sites(env) })

  const site = siteFor(env, url.searchParams.get('site'))
  if (!site) return json({ error: 'unknown site' }, 404)

  if (path === '/api/summary' && request.method === 'GET') {
    const [checks, origins, csp, alerts] = await Promise.all([
      env.DB.prepare('SELECT ts, ok, status, ms, error FROM checks WHERE site = ? ORDER BY ts DESC LIMIT 96').bind(site).all(),
      env.DB.prepare('SELECT origin, source, first_seen, last_seen, hits, approved FROM script_origins WHERE site = ? ORDER BY approved, first_seen DESC').bind(site).all(),
      env.DB.prepare('SELECT directive, blocked, count, last_seen, sample FROM csp_reports WHERE site = ? ORDER BY count DESC LIMIT 50').bind(site).all(),
      env.DB.prepare('SELECT id, ts, kind, message, acked FROM alerts WHERE site = ? ORDER BY ts DESC LIMIT 50').bind(site).all()
    ])
    return json({
      checks: checks.results.map((r) => ({ ts: r.ts, ok: r.ok === 1, status: r.status, ms: r.ms, error: r.error || undefined })),
      origins: origins.results.map((r) => ({ origin: r.origin, source: r.source, firstSeen: r.first_seen, lastSeen: r.last_seen, hits: r.hits, approved: r.approved === 1 })),
      csp: csp.results.map((r) => ({ directive: r.directive, blocked: r.blocked, count: r.count, lastSeen: r.last_seen, sample: r.sample || undefined })),
      alerts: alerts.results.map((r) => ({ id: r.id, ts: r.ts, kind: r.kind, message: r.message, acked: r.acked === 1 }))
    })
  }
  if (path === '/api/approve' && request.method === 'POST') {
    const body = await readBody(request)
    if (!body || typeof body.origin !== 'string') return json({ error: 'bad request' }, 400)
    await env.DB.prepare('UPDATE script_origins SET approved = ? WHERE site = ? AND origin = ?').bind(body.approved ? 1 : 0, site, body.origin).run()
    return json({ ok: true })
  }
  if (path === '/api/ack' && request.method === 'POST') {
    await env.DB.prepare('UPDATE alerts SET acked = 1 WHERE site = ?').bind(site).run()
    return json({ ok: true })
  }
  return json({ error: 'not found' }, 404)
}


// ---------- Oracle VM agent mailbox ----------

async function vmSettings(env) {
  try {
    return { ...VM_DEFAULTS, ...JSON.parse((await getState(env, 'vm:settings')) || '{}') }
  } catch {
    return { ...VM_DEFAULTS }
  }
}

/** Counts high/critical issues in raw scanner output, for alerts only (the desktop does the real parsing). */
function countHigh(nuclei, zap) {
  let n = 0
  for (const line of nuclei.split('\n')) {
    if (!line.startsWith('{')) continue
    try {
      const sev = String(JSON.parse(line).info?.severity || '').toLowerCase()
      if (sev === 'high' || sev === 'critical') n++
    } catch {
      // ignore
    }
  }
  try {
    for (const site of JSON.parse(zap || '{}').site || []) for (const a of site.alerts || []) if (a.riskcode === '3' && a.confidence !== '0') n++
  } catch {
    // ignore
  }
  return n
}

async function handleVm(request, env, ctx, url) {
  const path = url.pathname
  // --- called by the VM ---
  if (path === '/api/vm/config' || path === '/api/vm/heartbeat' || path === '/api/vm/result') {
    if (!bearerMatches(request, env.VM_TOKEN)) return json({ error: 'unauthorized' }, 401)
    if (path === '/api/vm/config' && request.method === 'GET') {
      const cutoff = new Date(Date.now() - 24 * 3600_000).toISOString()
      await env.DB.prepare('UPDATE vm_jobs SET done_at = ? WHERE done_at IS NULL AND requested_at < ?').bind('expired', cutoff).run()
      const jobs = await env.DB.prepare('SELECT id, site, requested_at FROM vm_jobs WHERE done_at IS NULL ORDER BY id').all()
      return json({ sites: sites(env), settings: await vmSettings(env), jobs: jobs.results, now: now() })
    }
    if (path === '/api/vm/heartbeat' && request.method === 'POST') {
      const b = (await readBody(request)) || {}
      const hb = { ts: now(), hostname: clip(b.hostname, 100), agentVersion: clip(b.agentVersion, 20), diskFreeGb: Number(b.diskFreeGb) || null, state: clip(b.state, 20), site: clip(b.site, 255) }
      await setState(env, 'vm:heartbeat', JSON.stringify(hb))
      return json({ ok: true })
    }
    if (path === '/api/vm/result' && request.method === 'POST') {
      const b = await readBody(request, MAX_VM_BODY)
      const site = b && siteFor(env, b.site)
      if (!site) return json({ error: 'bad request' }, 400)
      const nuclei = String(b.nuclei || '').slice(0, MAX_VM_FIELD)
      const zap = String(b.zap || '').slice(0, MAX_VM_FIELD)
      const errors = JSON.stringify((Array.isArray(b.errors) ? b.errors : []).slice(0, 5).map((e) => clip(e, 500)))
      const high = countHigh(nuclei, zap)
      const r = await env.DB.prepare(
        'INSERT INTO vm_results (site, started_at, finished_at, received_at, nuclei, zap, errors, agent_version, high) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(site, clip(b.startedAt, 40), clip(b.finishedAt, 40), now(), nuclei, zap, errors, clip(b.agentVersion, 20), high).run()
      if (b.jobId) await env.DB.prepare('UPDATE vm_jobs SET done_at = ? WHERE id = ? AND site = ?').bind(now(), Number(b.jobId), site).run()
      await env.DB.prepare('DELETE FROM vm_results WHERE site = ? AND id NOT IN (SELECT id FROM vm_results WHERE site = ? ORDER BY id DESC LIMIT 30)').bind(site, site).run()
      if (high) await alert(env, ctx, site, 'deep_scan', `Scheduled deep scan found ${high} high or critical issue(s). Open SiteWarden for details.`)
      return json({ ok: true, id: r.meta?.last_row_id ?? null })
    }
    return json({ error: 'not found' }, 404)
  }

  // --- called by the desktop app ---
  if (!authorized(request, env)) return json({ error: 'unauthorized' }, 401)
  if (path === '/api/vm/status' && request.method === 'GET') {
    const [hb, jobs, latest] = await Promise.all([
      getState(env, 'vm:heartbeat'),
      env.DB.prepare('SELECT id, site, requested_at FROM vm_jobs WHERE done_at IS NULL ORDER BY id').all(),
      env.DB.prepare('SELECT id, site, finished_at, errors, high FROM vm_results WHERE id IN (SELECT MAX(id) FROM vm_results GROUP BY site)').all()
    ])
    return json({
      tokenConfigured: Boolean(env.VM_TOKEN),
      heartbeat: hb ? JSON.parse(hb) : null,
      settings: await vmSettings(env),
      jobs: jobs.results.map((j) => ({ id: j.id, site: j.site, requestedAt: j.requested_at })),
      latest: latest.results.map((r) => ({ id: r.id, site: r.site, finishedAt: r.finished_at, errors: JSON.parse(r.errors), high: r.high }))
    })
  }
  if (path === '/api/vm/scan' && request.method === 'POST') {
    const site = siteFor(env, url.searchParams.get('site'))
    if (!site) return json({ error: 'unknown site' }, 404)
    const pending = await env.DB.prepare('SELECT id FROM vm_jobs WHERE site = ? AND done_at IS NULL').bind(site).first()
    if (!pending) await env.DB.prepare('INSERT INTO vm_jobs (site, requested_at) VALUES (?, ?)').bind(site, now()).run()
    return json({ ok: true, alreadyQueued: Boolean(pending) })
  }
  if (path === '/api/vm/results' && request.method === 'GET') {
    const since = Number(url.searchParams.get('since') || 0)
    const rows = await env.DB.prepare(
      'SELECT id, site, started_at, finished_at, nuclei, zap, errors, agent_version FROM vm_results WHERE id > ? ORDER BY id LIMIT 5'
    ).bind(since).all()
    return json({
      results: rows.results.map((r) => ({ id: r.id, site: r.site, startedAt: r.started_at, finishedAt: r.finished_at, nuclei: r.nuclei, zap: r.zap, errors: JSON.parse(r.errors), agentVersion: r.agent_version }))
    })
  }
  if (path === '/api/vm/settings' && request.method === 'POST') {
    const b = await readBody(request)
    if (!b) return json({ error: 'bad request' }, 400)
    const n = (v, lo, hi, d) => (Number.isFinite(Number(v)) ? Math.min(hi, Math.max(lo, Math.round(Number(v)))) : d)
    const settings = {
      enabled: b.enabled !== false,
      intervalHours: n(b.intervalHours, 1, 720, 24),
      nucleiRate: n(b.nucleiRate, 1, 150, 20),
      nucleiMaxMinutes: n(b.nucleiMaxMinutes, 2, 180, 30),
      nucleiInteractsh: b.nucleiInteractsh === true,
      zapSpiderMinutes: n(b.zapSpiderMinutes, 1, 30, 3),
      zapMaxMinutes: n(b.zapMaxMinutes, 3, 120, 15)
    }
    await setState(env, 'vm:settings', JSON.stringify(settings))
    return json({ ok: true, settings })
  }
  return json({ error: 'not found' }, 404)
}

// ---------- scheduled checks ----------

function scriptOrigins(html, base) {
  const out = new Set()
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) {
    try {
      const u = new URL(m[1], base)
      out.add(u.origin + u.pathname)
    } catch {
      // ignore
    }
  }
  return [...out]
}

async function checkSite(env, ctx, site) {
  const started = Date.now()
  let ok = false
  let status = 0
  let error = null
  let html = ''
  let finalUrl = `https://${site}/`
  try {
    const res = await fetch(finalUrl, { headers: { 'User-Agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(15000) })
    status = res.status
    finalUrl = res.url || finalUrl
    ok = res.status < 500
    if ((res.headers.get('content-type') || '').includes('html')) html = (await res.text()).slice(0, 1_000_000)
  } catch (e) {
    error = clip(e && e.message, 200)
  }
  const ms = Date.now() - started
  await env.DB.prepare('INSERT INTO checks (site, ts, ok, status, ms, error) VALUES (?, ?, ?, ?, ?, ?)').bind(site, now(), ok ? 1 : 0, status, ms, error).run()

  // Down after two consecutive failures; one alert per outage.
  const downKey = `down:${site}`
  if (!ok) {
    const prev = await env.DB.prepare('SELECT ok FROM checks WHERE site = ? ORDER BY ts DESC LIMIT 1 OFFSET 1').bind(site).first()
    if (prev && prev.ok === 0 && !(await getState(env, downKey))) {
      await setState(env, downKey, now())
      await alert(env, ctx, site, 'down', `Site is down: ${error || 'HTTP ' + status}`)
    }
  } else if (await getState(env, downKey)) {
    await setState(env, downKey, null)
    await alert(env, ctx, site, 'recovered', 'Site is reachable again.')
  }

  if (html) {
    const external = scriptOrigins(html, finalUrl).filter((s) => !sameSite(s, site))
    const { fresh, baseline } = await recordOrigins(env, site, external, 'crawl')
    if (fresh.length && !baseline) {
      await alert(env, ctx, site, 'new_script', `New third-party script in your homepage HTML: ${fresh.slice(0, 5).join(', ')}`)
    }
  }

  if (env.SB_KEY) {
    try {
      const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(env.SB_KEY)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'sitewarden-agent', clientVersion: VERSION },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: `https://${site}/` }, { url: `http://${site}/` }]
          }
        })
      })
      if (r.ok) {
        const data = await r.json()
        const flagged = Boolean(data.matches && data.matches.length)
        const key = `sb:${site}`
        if (flagged && !(await getState(env, key))) {
          await setState(env, key, now())
          await alert(env, ctx, site, 'blacklisted', `Google Safe Browsing flags the site: ${[...new Set(data.matches.map((m) => m.threatType))].join(', ')}`)
        } else if (!flagged && (await getState(env, key))) {
          await setState(env, key, null)
          await alert(env, ctx, site, 'delisted', 'Google Safe Browsing no longer flags the site.')
        }
      }
    } catch {
      // try again next run
    }
  }

  if (env.URLHAUS_KEY) {
    try {
      const r = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
        method: 'POST',
        headers: { 'Auth-Key': env.URLHAUS_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ host: site }).toString()
      })
      if (r.ok) {
        const data = await r.json()
        const online = (data.urls || []).filter((u) => u.url_status === 'online')
        const key = `urlhaus:${site}`
        if (online.length && !(await getState(env, key))) {
          await setState(env, key, now())
          await alert(env, ctx, site, 'malware', `URLhaus lists ${online.length} live malware URL(s) on the site.`)
        } else if (!online.length && (await getState(env, key))) {
          await setState(env, key, null)
        }
      }
    } catch {
      // try again next run
    }
  }
}

async function prune(env) {
  const cutoff = (days) => new Date(Date.now() - days * 86_400_000).toISOString()
  await env.DB.batch([
    env.DB.prepare('DELETE FROM checks WHERE ts < ?').bind(cutoff(30)),
    env.DB.prepare('DELETE FROM alerts WHERE ts < ?').bind(cutoff(90)),
    env.DB.prepare('DELETE FROM csp_reports WHERE last_seen < ?').bind(cutoff(30))
  ])
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })
    if (url.pathname === '/guard.js' && request.method === 'GET') {
      const sample = Math.min(1, Math.max(0, Number(env.GUARD_SAMPLE || '0.1')))
      return new Response(GUARD_SOURCE.replace('__SAMPLE__', String(sample)), {
        headers: { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'public, max-age=3600', 'Access-Control-Allow-Origin': '*' }
      })
    }
    await ensureSchema(env)
    if (url.pathname === '/r/guard' && request.method === 'POST') return handleGuard(request, env, ctx, url)
    if (url.pathname === '/r/csp' && request.method === 'POST') return handleCsp(request, env, url)
    if (url.pathname.startsWith('/api/vm/')) return handleVm(request, env, ctx, url)
    if (url.pathname.startsWith('/api/')) return handleApi(request, env, url)
    return new Response('SiteWarden agent ' + VERSION, { headers: { 'Content-Type': 'text/plain' } })
  },

  async scheduled(_event, env, ctx) {
    await ensureSchema(env)
    for (const site of sites(env)) {
      try {
        await checkSite(env, ctx, site)
      } catch (e) {
        console.error('check failed', site, e)
      }
    }
    await prune(env)
  }
}
