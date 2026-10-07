import Link from 'next/link'
import { BLOB, NAV, RELEASE, REPO_URL } from '@/lib/site'

export function SiteFooter() {
  return (
    <footer style={{ borderTop: '1px solid #E7E5E4', color: '#A8A29E' }}>
      <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-8 text-[13px] sm:flex-row sm:items-center sm:justify-between sm:px-8">
        <p>Agent Mesh Protocol · release {RELEASE} · Apache 2.0</p>
        <div className="flex flex-wrap gap-x-5 gap-y-2">
          {NAV.map(({ href, label }) => (
            <Link key={href} href={href} className="hover:underline">
              {label}
            </Link>
          ))}
          <a href={`${BLOB}/CHANGELOG.md`} target="_blank" rel="noopener noreferrer" className="hover:underline">
            Changelog
          </a>
          <a href={`${BLOB}/LICENSE`} target="_blank" rel="noopener noreferrer" className="hover:underline">
            License
          </a>
          <a href={REPO_URL} target="_blank" rel="noopener noreferrer" className="hover:underline">
            GitHub
          </a>
        </div>
      </div>
    </footer>
  )
}
