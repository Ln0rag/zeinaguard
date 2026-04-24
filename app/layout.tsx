import type { Metadata } from 'next'
import { Geist, Geist_Mono } from 'next/font/google'
import { Toaster } from 'sonner'
import { ThemeProvider } from 'next-themes'
import { NotificationProvider } from '@/context/notification-context'
import './globals.css'

const _geist = Geist({ subsets: ["latin"] });
const _geistMono = Geist_Mono({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: 'ZeinaGuard',
  description: 'Rouge Access Points Detection and Prevention System',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="font-sans antialiased">
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem>
          <NotificationProvider>
            {children}
            <Toaster 
              position="bottom-center"
              richColors
              theme="system"
            />
          </NotificationProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
