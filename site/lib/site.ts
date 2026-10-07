/**
 * Site-wide constants. Copy on the site follows the repository README and
 * CHANGELOG for the current release; keep them in sync when either changes.
 */

export const REPO_URL = 'https://github.com/agentmeshpro/agent-mesh-protocol'
export const BLOB = `${REPO_URL}/blob/main`
export const TREE = `${REPO_URL}/tree/main`
export const INSTALL_CMD = 'pip install ampro'
export const INSTALL_ALL_CMD = 'pip install "ampro[all]"'
export const INSTALL_MAIN_CMD =
  'pip install "ampro[all] @ git+https://github.com/agentmeshpro/agent-mesh-protocol.git"'
export const PYPI_URL = 'https://pypi.org/project/ampro/'
export const RELEASES_URL = `${REPO_URL}/releases`
export const EXT_URI = 'https://github.com/agentmeshpro/agent-mesh-protocol/ext/amp/v1'
export const RELEASE = '0.5.0'

export const MONO = "var(--font-space-mono), ui-monospace, SFMono-Regular, Menlo, monospace"
export const SERIF = "var(--font-newsreader), 'Newsreader', Georgia, serif"
export const ACCENT = '#C86948'

/**
 * The live demo (the /demo page and the /api/amp-demo routes, which spend
 * AI Gateway credit) is off unless NEXT_PUBLIC_AMP_DEMO_ENABLED is "true".
 * The value is read at build time, so changing it needs a redeploy.
 */
export const DEMO_ENABLED = process.env.NEXT_PUBLIC_AMP_DEMO_ENABLED === 'true'

const ALL_NAV = [
  { href: '/demo', label: 'Demo' },
  { href: '/protocol', label: 'Why AMP' },
  { href: '/docs', label: 'Docs' },
  { href: '/releases', label: 'Releases' },
] as const

export const NAV = ALL_NAV.filter((item) => DEMO_ENABLED || item.href !== '/demo')
