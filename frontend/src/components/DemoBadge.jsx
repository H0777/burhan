import { isDemoMode } from '../config/runtime'

/**
 * H14 — DEMO badge, tied to the RUNTIME configuration (R13 pattern).
 *
 * Reads the RESOLVED runtime config on every render via isDemoMode() — never a
 * build-time constant. Rendering contract:
 *  - app_mode === "demo"          -> slim fixed banner at the very top.
 *  - app_mode === "institutional" -> renders NOTHING (institutional users must
 *    never see demo UI).
 *  - config not loaded yet        -> renders NOTHING (isDemoMode() is false
 *    while resolvedRuntimeConfig is null).
 *
 * Non-intrusive by construction: 24px tall, pointer-events-none (clicks pass
 * through), and App.jsx reserves the strip in demo mode (root pt-6 / header
 * sticky top-6) so no content ever sits underneath it.
 */
export function DemoBadge() {
  if (!isDemoMode()) return null

  return (
    <div
      data-testid="demo-badge"
      role="status"
      aria-label="Demo environment banner"
      dir="ltr"
      className="fixed top-0 left-0 right-0 z-50 h-6 flex items-center justify-center bg-amber-400 text-black border-b border-amber-600 shadow-md select-none pointer-events-none"
    >
      <span className="text-[11px] font-bold tracking-wide font-mono truncate px-2">
        DEMO — نسخة تجريبية (بيانات وشبكة محلية)
      </span>
    </div>
  )
}
