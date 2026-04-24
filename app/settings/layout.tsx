import { AppLayout } from '@/components/layout/app-layout';

export const metadata = {
  title: 'Settings - ZeinaGuard Pro',
  description: 'System Settings and Developer Tools',
};

export default function SettingsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppLayout>{children}</AppLayout>;
}
