// SQLite store (Node's built-in node:sqlite, so there is no native module to rebuild for Electron).
// On first run it imports the phase-1 JSON file and keeps it as *.migrated.
import { app } from 'electron'
import { existsSync, mkdirSync, readFileSync, renameSync } from 'fs'
import { join } from 'path'
import { DatabaseSync } from 'node:sqlite'
import type { CfChange, Domain, ScanResult } from '../shared/types'

const MAX_SCANS_PER_DOMAIN = 50

let db: DatabaseSync | null = null

function open(): DatabaseSync {
  if (db) return db
  const dir = app.getPath('userData')
  mkdirSync(dir, { recursive: true })
  db = new DatabaseSync(join(dir, 'sitewarden.db'))
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS domains (
      id TEXT PRIMARY KEY,
      host TEXT NOT NULL UNIQUE,
      added_at TEXT NOT NULL,
      token TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0,
      verified_at TEXT,
      verified_by TEXT
    );
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
      host TEXT NOT NULL,
      started_at TEXT NOT NULL,
      finished_at TEXT NOT NULL,
      score INTEGER NOT NULL,
      grade TEXT NOT NULL,
      findings TEXT NOT NULL,
      checks TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS scans_by_domain ON scans(domain_id, started_at DESC);
    CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS cf_changes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
      zone_id TEXT NOT NULL,
      item TEXT NOT NULL,
      label TEXT NOT NULL,
      previous TEXT NOT NULL,
      applied TEXT NOT NULL,
      applied_at TEXT NOT NULL,
      reverted_at TEXT
    );
  `)
  const cols = (db.prepare('PRAGMA table_info(scans)').all() as { name: string }[]).map((c) => c.name)
  if (!cols.includes('origin')) db.exec("ALTER TABLE scans ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'")
  migrateJson(db, dir)
  return db
}

function migrateJson(d: DatabaseSync, dir: string): void {
  const p = join(dir, 'sitewarden-data.json')
  if (!existsSync(p)) return
  try {
    const data = JSON.parse(readFileSync(p, 'utf8')) as { domains?: Domain[]; scans?: ScanResult[] }
    d.exec('BEGIN')
    for (const dom of data.domains ?? []) writeDomain(d, dom)
    for (const s of data.scans ?? []) writeScan(d, s)
    d.exec('COMMIT')
    renameSync(p, `${p}.migrated`)
  } catch (e) {
    try {
      d.exec('ROLLBACK')
    } catch {
      // no open transaction
    }
    console.error('JSON migration failed; the old file was left in place', e)
  }
}

type Row = Record<string, unknown>

function toDomain(r: Row): Domain {
  return {
    id: r.id as string,
    host: r.host as string,
    addedAt: r.added_at as string,
    verificationToken: r.token as string,
    verified: r.verified === 1,
    verifiedAt: (r.verified_at as string | null) ?? undefined,
    verifiedBy: ((r.verified_by as string | null) ?? undefined) as Domain['verifiedBy']
  }
}

function toScan(r: Row): ScanResult {
  return {
    id: r.id as string,
    domainId: r.domain_id as string,
    host: r.host as string,
    startedAt: r.started_at as string,
    finishedAt: r.finished_at as string,
    score: r.score as number,
    grade: r.grade as string,
    findings: JSON.parse(r.findings as string),
    checks: JSON.parse(r.checks as string),
    origin: (r.origin as ScanResult['origin']) ?? 'local'
  }
}

function writeDomain(d: DatabaseSync, x: Domain): void {
  d.prepare(
    `INSERT INTO domains (id, host, added_at, token, verified, verified_at, verified_by)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET host=excluded.host, token=excluded.token, verified=excluded.verified,
       verified_at=excluded.verified_at, verified_by=excluded.verified_by`
  ).run(x.id, x.host, x.addedAt, x.verificationToken, x.verified ? 1 : 0, x.verifiedAt ?? null, x.verifiedBy ?? null)
}

function writeScan(d: DatabaseSync, s: ScanResult): void {
  d.prepare(
    `INSERT OR REPLACE INTO scans (id, domain_id, host, started_at, finished_at, score, grade, findings, checks, origin)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(s.id, s.domainId, s.host, s.startedAt, s.finishedAt, s.score, s.grade, JSON.stringify(s.findings), JSON.stringify(s.checks), s.origin ?? 'local')
}

export const store = {
  domains(): Domain[] {
    return (open().prepare('SELECT * FROM domains ORDER BY host').all() as Row[]).map(toDomain)
  },
  domain(id: string): Domain | undefined {
    const r = open().prepare('SELECT * FROM domains WHERE id = ?').get(id) as Row | undefined
    return r ? toDomain(r) : undefined
  },
  upsertDomain(d: Domain): void {
    writeDomain(open(), d)
  },
  removeDomain(id: string): void {
    open().prepare('DELETE FROM domains WHERE id = ?').run(id) // scans and change log cascade
  },
  scans(domainId: string): ScanResult[] {
    return (open().prepare('SELECT * FROM scans WHERE domain_id = ? ORDER BY started_at DESC').all(domainId) as Row[]).map(toScan)
  },
  scan(id: string): ScanResult | undefined {
    const r = open().prepare('SELECT * FROM scans WHERE id = ?').get(id) as Row | undefined
    return r ? toScan(r) : undefined
  },
  addScan(s: ScanResult): void {
    const d = open()
    writeScan(d, s)
    d.prepare(
      `DELETE FROM scans WHERE domain_id = ? AND id NOT IN
         (SELECT id FROM scans WHERE domain_id = ? ORDER BY started_at DESC LIMIT ?)`
    ).run(s.domainId, s.domainId, MAX_SCANS_PER_DOMAIN)
  },

  get<T>(key: string): T | undefined {
    const r = open().prepare('SELECT v FROM kv WHERE k = ?').get(key) as { v: string } | undefined
    return r ? (JSON.parse(r.v) as T) : undefined
  },
  set(key: string, value: unknown): void {
    if (value === undefined) open().prepare('DELETE FROM kv WHERE k = ?').run(key)
    else open().prepare('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').run(key, JSON.stringify(value))
  },

  addChange(c: Omit<CfChange, 'id' | 'revertedAt'>): number {
    const r = open()
      .prepare('INSERT INTO cf_changes (domain_id, zone_id, item, label, previous, applied, applied_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(c.domainId, c.zoneId, c.item, c.label, c.previous, c.applied, c.appliedAt)
    return Number(r.lastInsertRowid)
  },
  changes(domainId: string): CfChange[] {
    return (open().prepare('SELECT * FROM cf_changes WHERE domain_id = ? ORDER BY id DESC').all(domainId) as Row[]).map((r) => ({
      id: r.id as number,
      domainId: r.domain_id as string,
      zoneId: r.zone_id as string,
      item: r.item as string,
      label: r.label as string,
      previous: r.previous as string,
      applied: r.applied as string,
      appliedAt: r.applied_at as string,
      revertedAt: (r.reverted_at as string | null) ?? undefined
    }))
  },
  change(id: number): CfChange | undefined {
    const r = open().prepare('SELECT domain_id FROM cf_changes WHERE id = ?').get(id) as Row | undefined
    return r ? this.changes(r.domain_id as string).find((c) => c.id === id) : undefined
  },
  markReverted(id: number): void {
    open().prepare('UPDATE cf_changes SET reverted_at = ? WHERE id = ?').run(new Date().toISOString(), id)
  }
}
