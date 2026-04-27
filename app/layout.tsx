import type { Metadata } from 'next'
import { Geist, Geist_Mono } from 'next/font/google'
import { Toaster } from 'sonner'
import { ThemeProvider } from 'next-themes'
// 🔴 شلنا الـ NotificationProvider لأنه غالباً اتمسح مع الإعدادات
import '@/styles/globals.css'

const geistSans = Geist({
  subsets: ["latin"],
  variable: "--font-sans", // تعريف المتغير للخط
});

const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: 'ZeinaGuard',
  description: 'Rogue Access Points Detection and Prevention System',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      {/* تطبيق الخطوط والـ Variables على الـ body */}
      <body className={`${geistSans.variable} ${geistMono.variable} font-sans antialiased`}>
        <ThemeProvider 
          attribute="class" 
          defaultTheme="system" // خليناه نظام عشان يطابق الجهاز أوتوماتيك
          enableSystem
          disableTransitionOnChange
        >
          {/* شلنا الـ NotificationProvider عشان ميعملش Error "Module not found" */}
          <main>
            {children}
          </main>
          
          <Toaster 
            position="bottom-center"
            richColors
            theme="system"
          />
        </ThemeProvider>
      </body>
    </html>
  )
}