import { AppLayout } from '@/components/layout/app-layout';

export const metadata = {
  title: 'Dashboard - ZeinaGuard',
  description: 'Wireless Intrusion Detection and Prevention System Dashboard',
};

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppLayout>{children}</AppLayout>;
}
