import { NextResponse } from 'next/server'
import {
  ensureDemoKeys,
  listPublicKeys,
} from '@/demo/trust/keystore'

const YOUR_AGENT = 'agent://you@example.com'
const SUNNY_BAKERY = 'agent://sunny-bakery.example.com'
const PORTER_DELIVERY = 'agent://porter.example.com'
const DIRECTORY = 'agent://directory.amp.example.com'

export async function GET() {
  try {
    await ensureDemoKeys([
      YOUR_AGENT,
      SUNNY_BAKERY,
      PORTER_DELIVERY,
      DIRECTORY,
    ])
    const keys = await listPublicKeys()
    return NextResponse.json(
      {
        alg: 'Ed25519',
        keys,
      },
      {
        headers: {
          // The client fetches this once; the process keeps keys in
          // memory across requests so this response is stable until the
          // server restarts. Short browser cache is fine.
          'Cache-Control': 'public, max-age=30',
        },
      },
    )
  } catch (err) {
    console.error('[amp-demo/keys]', err)
    return NextResponse.json(
      { error: 'Failed to expose keys', details: String(err) },
      { status: 500 },
    )
  }
}
