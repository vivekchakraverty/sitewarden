/** Electron wraps IPC errors as "Error invoking remote method 'x': Error: message". Keep only the message. */
export function errMsg(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e)
  return m.replace(/^Error invoking remote method '[^']+': (Error: )?/, '')
}

export async function copy(text: string): Promise<void> {
  await navigator.clipboard.writeText(text)
}
