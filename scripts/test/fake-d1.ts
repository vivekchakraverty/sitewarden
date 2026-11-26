// Minimal D1 binding on top of node:sqlite, enough for the agent Worker.
import { DatabaseSync } from 'node:sqlite'
export function fakeD1() {
  const db = new DatabaseSync(':memory:')
  const stmt = (sql: string, args: unknown[] = []) => ({
    bind: (...a: unknown[]) => stmt(sql, a),
    run: async () => { db.prepare(sql).run(...(args as never[])); return { success: true } },
    all: async () => ({ results: db.prepare(sql).all(...(args as never[])) }),
    first: async () => db.prepare(sql).get(...(args as never[])) ?? null,
    _exec: () => db.prepare(sql).run(...(args as never[]))
  })
  return {
    prepare: (sql: string) => stmt(sql),
    batch: async (list: ReturnType<typeof stmt>[]) => { db.exec('BEGIN'); try { for (const s of list) s._exec(); db.exec('COMMIT') } catch (e) { db.exec('ROLLBACK'); throw e } return [] },
    raw: db
  }
}
