// Stands in for Electron's main-process APIs in Node tests.
import { tmpdir } from 'os'
export const app = { getPath: (name: string) => (name === 'temp' ? tmpdir() : (process.env.SW_TEST_DIR as string)) }
export const safeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (s: string) => Buffer.from('enc:' + s),
  decryptString: (b: Buffer) => b.toString().replace(/^enc:/, '')
}
