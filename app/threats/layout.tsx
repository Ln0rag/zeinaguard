import { AppLayout } from '@/components/layout/app-layout';

export const metadata = {
  title: 'Threats - ZeinaGuard Pro',
  description: 'Real-time threat detection and management',
};

export default function ThreatsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppLayout>{children}</AppLayout>;
}
