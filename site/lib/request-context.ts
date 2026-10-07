import { AsyncLocalStorage } from 'node:async_hooks'
import { LIMITS } from './limits'

/**
 * Per-request state for the demo routes.
 *
 * Route handlers run their work inside `withRequestContext`. Helpers deep
 * in the call graph read it without threading parameters through:
 *
 * - `modelSignal()` returns the `abortSignal` for a model call. It fires
 *   when the client disconnects (request.signal), when the whole request
 *   exceeds AMP_DEMO_REQUEST_TIMEOUT_MS, or when that single call
 *   exceeds AMP_DEMO_MODEL_TIMEOUT_MS.
 * - `taskIds` lets the envelope builder reuse one `task_id` for every
 *   envelope exchanged between the same two agents within a request.
 */
type RequestContext = {
  signal: AbortSignal
  taskIds: Map<string, string>
}

const storage = new AsyncLocalStorage<RequestContext>()

export function requestSignal(request: Request, timeoutMs = LIMITS.requestTimeoutMs): AbortSignal {
  return AbortSignal.any([request.signal, AbortSignal.timeout(timeoutMs)])
}

export function withRequestContext<T>(signal: AbortSignal, fn: () => T): T {
  return storage.run({ signal, taskIds: new Map() }, fn)
}

export function modelSignal(): AbortSignal {
  const perCall = AbortSignal.timeout(LIMITS.modelCallTimeoutMs)
  const outer = storage.getStore()?.signal
  return outer ? AbortSignal.any([outer, perCall]) : perCall
}

/** True once the surrounding request was cancelled or timed out. */
export function requestAborted(): boolean {
  return storage.getStore()?.signal.aborted ?? false
}

/** Task-id registry for the current request (a fresh map outside one). */
export function requestTaskIds(): Map<string, string> {
  return storage.getStore()?.taskIds ?? new Map()
}
