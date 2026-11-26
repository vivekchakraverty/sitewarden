// Downloads the Electron binary after `npm install`, unless SITEWARDEN_SKIP_ELECTRON=1
// (CI test jobs don't need the ~100 MB runtime; packaging jobs do).
import { execFileSync } from 'child_process'
import { existsSync } from 'fs'

if (process.env.SITEWARDEN_SKIP_ELECTRON === '1') {
  console.log('SITEWARDEN_SKIP_ELECTRON=1: skipping the Electron binary download')
} else if (existsSync('node_modules/electron/install.js')) {
  execFileSync(process.execPath, ['node_modules/electron/install.js'], { stdio: 'inherit' })
}
