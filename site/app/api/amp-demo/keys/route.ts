/**
 * GET /api/amp-demo/keys
 *
 * Public-key directory for the demo agents. The browser fetches it once
 * and verifies every envelope's signature locally.
 *
 * Only PUBLIC keys are returned. Private keys stay inside
 * demo/trust/keystore.ts in server memory: they are never sent to the
 * client, never accepted from the client, never persisted and never
 * logged. This route takes no input.
 */

import { ensureDemoKeys, listPublicKeys } from '@/demo/trust/keystore'
import { demoDisabled, jsonError, logError } from '@/lib/api-guard'

const YOUR_AGENT = 'agent://you@example.com'
const SUNNY_BAKERY = 'agent://sunny-bakery.example.com'
const PORTER_DELIVERY = 'agent://porter.example.com'
const DIRECTORY = 'agent://directory.amp.example.com'

export const dynamic = 'force-dynamic'

export async function GET() {
  const disabled = demoDisabled()
  if (disabled) return disabled
  try {
    await ensureDemoKeys([YOUR_AGENT, SUNNY_BAKERY, PORTER_DELIVERY, DIRECTORY])
    const keys = await listPublicKeys()
    return Response.json(
      { alg: 'Ed25519', keys },
      {
        headers: {
          // Keys are stable for the life of a server instance (or across
          // instances when AMP_DEMO_SIGNING_SEED is set). Keep browser
          // caching short and never let shared caches mix instances.
          'Cache-Control': 'private, max-age=30',
        },
      },
    )
  } catch (err) {
    logError('amp-demo/keys', err)
    return jsonError(500, 'Key directory unavailable')
  }
}
