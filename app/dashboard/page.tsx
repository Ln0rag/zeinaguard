'use client';

import { LiveNetworkConsole } from '@/components/dashboard/live-network-console';


export default function DashboardPage() {
  return (
    <div className="flex-1 space-y-8 p-6 md:px-10 md:pt-4 md:pb-10 min-h-screen bg-slate-900 text-white font-sans">
      <LiveNetworkConsole />
    </div>
  );
}
