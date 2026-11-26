// Bundles the phase-2 test with Electron stubbed out and ?raw imports inlined, then runs it.
import { build } from 'esbuild'
import { readFileSync } from 'fs'
import { resolve, dirname } from 'path'
import { execFileSync } from 'child_process'
const raw = {
  name: 'raw',
  setup(b) {
    b.onResolve({ filter: /\?raw$/ }, (a) => ({ path: resolve(dirname(a.importer), a.path.replace(/\?raw$/, '')), namespace: 'raw' }))
    b.onLoad({ filter: /.*/, namespace: 'raw' }, (a) => ({ contents: readFileSync(a.path, 'utf8'), loader: 'text' }))
  }
}
const names = process.argv[2] ? [process.argv[2]] : ['phase2', 'phase3', 'phase4']
for (const name of names) {
  await build({
    entryPoints: [`scripts/test/${name}${name.includes('e2e') ? '' : '.test'}.ts`], bundle: true, platform: 'node', format: 'esm', outfile: `out/test/${name}.mjs`,
    alias: { electron: './scripts/test/electron-stub.ts' }, plugins: [raw], logLevel: 'warning', external: ['node:sqlite']
  })
  console.log(`
# ${name}`)
  execFileSync(process.execPath, [`out/test/${name}.mjs`], { stdio: 'inherit' })
}
