import type { Metadata } from 'next'
import { Newsreader, Space_Mono } from 'next/font/google'
import './globals.css'

const newsreader = Newsreader({
  subsets: ['latin'],
  weight: ['400'],
  variable: '--font-newsreader',
  display: 'swap',
})

const spaceMono = Space_Mono({
  subsets: ['latin'],
  weight: ['400', '700'],
  variable: '--font-space-mono',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'Agent Mesh Protocol',
  description: 'The open wire protocol for agent-to-agent communication.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`${newsreader.variable} ${spaceMono.variable}`}>
      <body className="min-h-dvh antialiased">{children}</body>
    </html>
  )
}
