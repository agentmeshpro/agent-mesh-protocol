import { SiteFooter } from '@/components/site-footer'
import { SiteNav } from '@/components/site-nav'
import { ButtonLink, PageHeader } from '@/components/content'

export default function NotFound() {
  return (
    <div className="flex min-h-dvh flex-col">
      <SiteNav />
      <main className="flex-1">
        <PageHeader eyebrow="404" title="This page does not exist">
          The link may be out of date. Everything on the site is reachable from the pages below.
        </PageHeader>
        <div className="mx-auto flex max-w-5xl flex-wrap gap-3 px-4 pb-20 sm:px-8">
          <ButtonLink href="/" primary>Home</ButtonLink>
          <ButtonLink href="/demo">Demo</ButtonLink>
          <ButtonLink href="/protocol">Why AMP</ButtonLink>
          <ButtonLink href="/docs">Docs</ButtonLink>
        </div>
      </main>
      <SiteFooter />
    </div>
  )
}
