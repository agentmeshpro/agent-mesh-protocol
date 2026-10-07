import type { NextConfig } from 'next'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const isDev = process.env.NODE_ENV !== 'production'

/**
 * Content Security Policy.
 *
 * - Scripts: Next.js injects inline bootstrap scripts, so 'unsafe-inline'
 *   is needed without a nonce middleware. Dev mode also needs
 *   'unsafe-eval' for React Refresh. No third-party script origins.
 * - Styles: the page uses inline style attributes and one inline <style>.
 * - Fonts: next/font self-hosts Google fonts under /_next.
 * - Images: the bakery agent's cake cards use Unsplash photos chosen by
 *   the model; every other origin is blocked, so model output cannot
 *   load arbitrary remote images.
 * - Connections: same origin only (the demo API routes).
 * - Audio is decoded from bytes with Web Audio, so no media origins.
 */
const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data: blob: https://images.unsplash.com",
  "media-src 'self' blob: data:",
  `connect-src 'self'${isDev ? ' ws: wss:' : ''}`,
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ')

const securityHeaders = [
  { key: 'Content-Security-Policy', value: csp },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  // The voice demo needs the microphone on this origin only.
  { key: 'Permissions-Policy', value: 'microphone=(self), camera=(), geolocation=(), payment=()' },
  ...(isDev
    ? []
    : [{ key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' }]),
]

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  turbopack: {
    root: path.dirname(fileURLToPath(import.meta.url)),
  },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}

export default nextConfig
