import type { Finding, KeyName } from '../../shared/types'
import type { FetchedPage } from '../http'

export interface ScanContext {
  host: string
  /** Homepage over HTTPS, fetched once and shared by checks. Undefined if it could not be loaded. */
  home?: FetchedPage
  homeError?: string
  key(name: KeyName): string | undefined
  /** Aborted when the user cancels the scan. */
  signal: AbortSignal
  /** Live status line for long-running checks. */
  note(text: string): void
}

export type CheckOutput = Finding[] | { skipped: string }

export interface Check {
  id: string
  name: string
  run(ctx: ScanContext): Promise<CheckOutput>
}
