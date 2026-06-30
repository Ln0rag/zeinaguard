import { AppLayout } from '@/components/layout/app-layout';

export const metadata = {
  title: 'Operation Center - ZeinaGuard',
  description: 'Autonomous Containment & Threat Lifecycle Management',
};

export default function OperationCenterLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppLayout>{children}</AppLayout>;
}
