import type { SiteWardenApi } from '../shared/types'

declare global {
  interface Window {
    sitewarden: SiteWardenApi
  }
}
