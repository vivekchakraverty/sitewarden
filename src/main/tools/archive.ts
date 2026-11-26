// Minimal, dependency-free extractors for the tool downloads (.zip and .tar.gz).
// Entries that would escape the destination folder (zip-slip) are rejected.
import { mkdirSync, writeFileSync, chmodSync } from 'fs'
import { dirname, isAbsolute, join, normalize, sep } from 'path'
import { gunzipSync, inflateRawSync } from 'zlib'

function safeJoin(dest: string, name: string): string | null {
  const clean = name.replace(/\\/g, '/')
  if (!clean || isAbsolute(clean) || /^[a-zA-Z]:/.test(clean)) return null
  const out = normalize(join(dest, clean))
  const root = normalize(dest.endsWith(sep) ? dest : dest + sep)
  if (!out.startsWith(root)) return null
  return out
}

export function extractZip(buf: Buffer, dest: string): number {
  // End of central directory record: last 22+ bytes, signature 0x06054b50.
  let eocd = -1
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i
      break
    }
  }
  if (eocd < 0) throw new Error('Not a zip file')
  const count = buf.readUInt16LE(eocd + 10)
  let p = buf.readUInt32LE(eocd + 16)
  if (count === 0xffff || p === 0xffffffff) throw new Error('Zip64 archives are not supported')
  let written = 0
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('Corrupt zip central directory')
    const method = buf.readUInt16LE(p + 10)
    const compSize = buf.readUInt32LE(p + 20)
    const nameLen = buf.readUInt16LE(p + 28)
    const extraLen = buf.readUInt16LE(p + 30)
    const commentLen = buf.readUInt16LE(p + 32)
    const extAttr = buf.readUInt32LE(p + 38)
    const localOff = buf.readUInt32LE(p + 42)
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen)
    p += 46 + nameLen + extraLen + commentLen

    const target = safeJoin(dest, name)
    if (!target) throw new Error(`Unsafe path in archive: ${name}`)
    if (name.endsWith('/')) {
      mkdirSync(target, { recursive: true })
      continue
    }
    if (buf.readUInt32LE(localOff) !== 0x04034b50) throw new Error('Corrupt zip local header')
    const dataStart = localOff + 30 + buf.readUInt16LE(localOff + 26) + buf.readUInt16LE(localOff + 28)
    const raw = buf.subarray(dataStart, dataStart + compSize)
    let data: Buffer
    if (method === 0) data = Buffer.from(raw)
    else if (method === 8) data = inflateRawSync(raw)
    else throw new Error(`Unsupported zip compression method ${method}`)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, data)
    const mode = (extAttr >>> 16) & 0o777
    if (mode && process.platform !== 'win32') chmodSync(target, mode)
    written++
  }
  return written
}

export function extractTarGz(buf: Buffer, dest: string): number {
  const tar = gunzipSync(buf)
  let p = 0
  let longName: string | null = null
  let paxPath: string | null = null
  let written = 0
  while (p + 512 <= tar.length) {
    const header = tar.subarray(p, p + 512)
    if (header.every((b) => b === 0)) break
    const str = (a: number, b: number): string => header.toString('utf8', a, b).replace(/\0.*$/s, '')
    const size = parseInt(str(124, 136).trim() || '0', 8)
    const type = String.fromCharCode(header[156] || 48)
    const mode = parseInt(str(100, 108).trim() || '644', 8)
    const prefix = str(345, 500)
    let name = longName ?? paxPath ?? (prefix ? `${prefix}/${str(0, 100)}` : str(0, 100))
    const body = tar.subarray(p + 512, p + 512 + size)
    p += 512 + Math.ceil(size / 512) * 512

    if (type === 'L') {
      longName = body.toString('utf8').replace(/\0.*$/s, '')
      continue
    }
    if (type === 'x') {
      const m = /\d+ path=([^\n]*)\n/.exec(body.toString('utf8'))
      paxPath = m ? m[1] : null
      continue
    }
    if (type === 'g') continue
    longName = null
    paxPath = null
    name = name.replace(/^\.\//, '')
    if (!name) continue
    const target = safeJoin(dest, name)
    if (!target) throw new Error(`Unsafe path in archive: ${name}`)
    if (type === '5') {
      mkdirSync(target, { recursive: true })
    } else if (type === '0' || type === '\0' || type === '7') {
      mkdirSync(dirname(target), { recursive: true })
      writeFileSync(target, body)
      if (process.platform !== 'win32') chmodSync(target, mode & 0o777)
      written++
    }
    // symlinks and hard links are skipped on purpose
  }
  return written
}
