// End-to-end check of the deep scanners with the real tools the app installed.
// Starts a deliberately vulnerable HTTPS site on localhost and runs the Nuclei and ZAP runners against it.
// Usage: npm run e2e:deep   (needs openssl on PATH, e.g. from Git for Windows)
import { execFileSync } from 'child_process'
import { mkdtempSync, readFileSync } from 'fs'
import { createServer } from 'https'
import { tmpdir } from 'os'
import { join } from 'path'
import type { Finding } from '../../src/shared/types'

const PORT = 8443
const host = `localhost:${PORT}`

function selfSignedCert(): { key: Buffer; cert: Buffer } {
  const d = mkdtempSync(join(tmpdir(), 'sw-cert-'))
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(d, 'k.pem'), '-out', join(d, 'c.pem'), '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' })
  return { key: readFileSync(join(d, 'k.pem')), cert: readFileSync(join(d, 'c.pem')) }
}

const pages: Record<string, { type: string; body: string }> = {
  '/': {
    type: 'text/html',
    body: `<!doctype html><html><head><title>Test shop</title><script src="/js/jquery-1.12.4.min.js"></script></head>
<body><h1>Test shop</h1><a href="/about">About</a> <a href="/login">Login</a> <a href="/search?q=shoes">Search</a>
<!-- TODO: remove debug user admin / password123 before launch --></body></html>`
  },
  '/about': { type: 'text/html', body: '<html><body><p>About us. Contact admin@example.test</p><a href="/">Home</a></body></html>' },
  '/login': {
    type: 'text/html',
    body: '<html><body><form method="post" action="/login"><input name="user"><input type="password" name="pass"><button>Go</button></form></body></html>'
  },
  '/search': { type: 'text/html', body: '<html><body>Results for your search</body></html>' },
  '/js/jquery-1.12.4.min.js': { type: 'application/javascript', body: '/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\nvar jQuery={};' },
  '/.git/config': { type: 'text/plain', body: '[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n[remote "origin"]\n\turl = https://example.test/shop.git\n' },
  '/.env': { type: 'text/plain', body: 'APP_ENV=production\nAPP_KEY=base64:c2VjcmV0c2VjcmV0c2VjcmV0\nDB_HOST=127.0.0.1\nDB_PASSWORD=hunter2\n' },
  '/phpinfo.php': { type: 'text/html', body: '<html><head><title>PHP 5.6.40 - phpinfo()</title></head><body><h1 class="p">PHP Version 5.6.40</h1></body></html>' }
}

async function main(): Promise<void> {
  process.env.SW_TEST_DIR = join(process.env.APPDATA ?? '', 'sitewarden') // use the tools the app installed
  const { key, cert } = selfSignedCert()
  let requests = 0
  const server = createServer({ key, cert }, (req, res) => {
    requests++
    const page = pages[(req.url ?? '/').split('?')[0]]
    res.setHeader('Server', 'Apache/2.4.29 (Ubuntu)')
    res.setHeader('X-Powered-By', 'PHP/5.6.40')
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Set-Cookie', 'session=abc123; Path=/')
    if (!page) {
      res.writeHead(404, { 'Content-Type': 'text/html' })
      res.end('<html><body>Not found</body></html>')
      return
    }
    res.writeHead(200, { 'Content-Type': page.type })
    res.end(page.body)
  })
  await new Promise<void>((r) => server.listen(PORT, '127.0.0.1', r))
  console.log(`vulnerable test site on https://${host}`)

  const { nucleiCheck } = await import('../../src/main/scanners/nuclei')
  const { zapCheck } = await import('../../src/main/scanners/zap')
  const ctx = { host, key: () => undefined, signal: new AbortController().signal, note: (t: string) => process.stdout.write(`\r  ${t.slice(0, 100).padEnd(100)}`) }

  let failed = false
  for (const check of [nucleiCheck, zapCheck]) {
    console.log(`\n== ${check.name}`)
    const t0 = Date.now()
    try {
      const out = await check.run(ctx)
      console.log('')
      if (!Array.isArray(out)) {
        console.log(`  SKIPPED: ${out.skipped}`)
        failed = true
        continue
      }
      for (const f of out as Finding[]) console.log(`  ${f.severity.padEnd(8)} ${f.title}${f.evidence ? `  [${f.evidence.split('\n')[0].slice(0, 70)}]` : ''}`)
      console.log(`  ${out.length} finding(s) in ${Math.round((Date.now() - t0) / 1000)}s, ${requests} requests so far`)
      if (!out.length) failed = true
    } catch (e) {
      console.log(`\n  ERROR: ${(e as Error).message}`)
      failed = true
    }
  }
  server.close()
  process.exit(failed ? 1 : 0)
}
void main()
