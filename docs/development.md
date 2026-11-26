# Development

Electron 43 · React 19 · TypeScript · electron-vite · Node's built-in `node:sqlite`, so there are no native modules to rebuild.

## Run from source

```bash
npm install          # also downloads the Electron binary
npm run dev          # app with hot reload
npm run typecheck
npm test             # phase 2–4 suites, no network
npm run smoke -- yourdomain.com   # passive quick checks from the CLI
npm run e2e:deep     # real Nuclei + ZAP against a vulnerable HTTPS site on localhost:8443 (needs openssl)
npm run build:win    # NSIS installer in release/
```

If `npm run dev` reports "Electron uninstall", run `node node_modules/electron/install.js`.

## Layout

```
src/main/             Electron main process
  index.ts            window, IPC handlers, first-launch setup
  store.ts            SQLite store (+ phase-1 JSON migration, schema migrations)
  secrets.ts          safeStorage-encrypted keys and tokens
  domains.ts          domain validation and ownership verification
  scanners/           one module per check; index.ts runs and scores them
    nuclei.ts zap.ts  deep-scan runners and output parsers
  fixes.ts            fix library (platform-specific remediation)
  report.ts           HTML report export
  csp.ts              CSP analyser/patcher for the guard script
  cloudflare/         API client, agent deploy, zone hardening, agent reader
  tools/              Nuclei/Java installers, ZAP detection, verified downloads, zip/tar extraction, auto-setup
  oracle/vm.ts        VM token, cloud-init builder, result import
src/worker/           agent.js (Cloudflare Worker) and guard.js (browser script), bundled as text
src/oracle/agent.py   the VM agent (Python standard library only)
src/preload/          typed contextBridge API (window.sitewarden)
src/renderer/         React UI
src/shared/types.ts   types shared by all processes
scripts/test/         test suites, fake D1, fake Docker, e2e harness
```

## Architecture notes

- **IPC:** the renderer can only call the typed functions in `src/preload/index.ts`. The main process validates every argument (`asString`, whitelists) and never returns secrets.
- **Worker deploy:** `src/worker/agent.js` is imported with `?raw`, `guard.js` is inlined into it, and both are uploaded through the multipart Workers Script API with D1, secret and plain-text bindings.
- **Hardening:** each item has `read`, `apply` and `restore`. Snapshots go to the `cf_changes` table; rules are added and removed by `ref` through per-rule ruleset endpoints.
- **Deep scans:** child processes are spawned without a shell, with an AbortSignal for cancel and a timeout. Nuclei progress comes from `-stats -sj` on stderr.
- **VM mailbox:** the `/api/vm/*` routes in the Worker. The VM token and agent token are checked separately.

## Tests

`npm test` bundles each suite with esbuild (Electron is stubbed by `scripts/test/electron-stub.ts`) and runs it with Node:

| Suite | Covers |
|---|---|
| phase2 | SQLite migration and retention; agent Worker (guard, CSP reports, cron, alerts, auth); deploy request shape; hardening apply/revert; CSP analyser and one-click fix |
| phase3 | zip/tar extraction and zip-slip rejection; checksum-verified downloads; Java/Nuclei/ZAP detection helpers; Nuclei args and parser; ZAP plan and parser |
| phase4 | VM mailbox auth separation, config, jobs, settings clamping; **real `agent.py`** with `fake_docker.py` against the real Worker code; desktop import; cloud-init structure |

`npm run e2e:deep` uses the real installed tools. The last run found 5 Nuclei findings in 12.6 minutes and 6 ZAP findings in 29 seconds.

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and on every pull request:

| Job | Runner | Does |
|---|---|---|
| Typecheck and tests | Windows and Ubuntu | `npm ci` (with `SITEWARDEN_SKIP_ELECTRON=1`, so the Electron binary isn't downloaded), `npm run typecheck`, `npm test` (Python 3.12 for the VM agent suite) |
| Package Windows installer | Windows | builds the NSIS installer and uploads it with its SHA-256 as a 7-day artifact |

`npm run e2e:deep` isn't run in CI because it needs the real Nuclei, ZAP and Java installs.

## Releasing

1. Bump `version` in `package.json` and add a `## X.Y.Z` section to `CHANGELOG.md`.
2. Commit, then tag and push: `git tag -a vX.Y.Z -m "SiteWarden X.Y.Z" && git push --follow-tags`.
3. `.github/workflows/release.yml` checks the tag matches `package.json`, runs typecheck and tests, builds the installer, and creates the GitHub release. The notes come from that version's changelog section, plus the installer's SHA-256. If the release already exists, only the installer is replaced. To rebuild an existing tag, run the workflow by hand (*Actions › Release › Run workflow*).
