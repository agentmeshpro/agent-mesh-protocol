'use client'

import { useEffect, useState } from 'react'
import { verifyEnvelope, type VerifyResult } from './verify'

/**
 * Run Web Crypto verification for a single envelope. Starts in
 * 'pending' and resolves to 'valid' / 'invalid' / 'unsigned' once the
 * async verify completes. Idempotent per-envelope id.
 */
export function useTrustVerification(envelope: {
  sender: string
  recipient: string
  id: string
  body_type: string
  headers: Record<string, string>
  body: Record<string, unknown>
}): VerifyResult {
  const [result, setResult] = useState<VerifyResult>({ state: 'pending' })

  useEffect(() => {
    let cancelled = false
    verifyEnvelope(envelope).then((r) => {
      if (!cancelled) setResult(r)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [envelope.id])

  return result
}
