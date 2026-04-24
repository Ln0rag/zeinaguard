import { AppLayout } from '@/components/layout/app-layout';

export const metadata = {
  title: 'Incidents - ZeinaGuard Pro',
  description: 'Incident response and management',
};

export default function IncidentsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppLayout>{children}</AppLayout>;
}
