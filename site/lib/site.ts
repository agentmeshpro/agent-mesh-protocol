/**
 * Site-wide constants. Copy on the site follows the repository README and
 * CHANGELOG for 0.4.0; keep them in sync when either changes.
 */

export const REPO_URL = 'https://github.com/agentmeshpro/agent-mesh-protocol'
export const BLOB = `${REPO_URL}/blob/main`
export const TREE = `${REPO_URL}/tree/main`
export const INSTALL_CMD =
  'pip install "ampro[all] @ git+https://github.com/agentmeshpro/agent-mesh-protocol.git"'
export const EXT_URI = 'https://github.com/agentmeshpro/agent-mesh-protocol/ext/amp/v1'
export const RELEASE = '0.4.0'

export const MONO = "var(--font-space-mono), ui-monospace, SFMono-Regular, Menlo, monospace"
export const SERIF = "var(--font-newsreader), 'Newsreader', Georgia, serif"
export const ACCENT = '#C86948'

export const NAV = [
  { href: '/demo', label: 'Demo' },
  { href: '/protocol', label: 'Why AMP' },
  { href: '/docs', label: 'Docs' },
] as const
