import type { Metadata } from 'next'
import { AmpClientRoot } from '@/demo/amp-client-root'

export const metadata: Metadata = {
  title: 'Live demo · Agent Mesh Protocol',
  description:
    'Order a cake from a bakery agent and watch the signed AMP envelopes flow between agents, as a chat, as protocol traffic, or by voice.',
}

export default function DemoPage() {
  return (
    <div className="h-dvh">
      <AmpClientRoot />
    </div>
  )
}
