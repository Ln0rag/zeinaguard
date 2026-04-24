import { AppLayout } from '@/components/layout/app-layout';

export const metadata = {
  title: 'Alerts - ZeinaGuard Pro',
  description: 'Alert rules and notification management',
};

export default function AlertsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppLayout>{children}</AppLayout>;
}
