import { AppLayout } from '@/components/layout/app-layout';

export const metadata = {
  title: 'Sensors - ZeinaGuard Pro',
  description: 'Wireless sensor management and monitoring',
};

export default function SensorsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppLayout>{children}</AppLayout>;
}
