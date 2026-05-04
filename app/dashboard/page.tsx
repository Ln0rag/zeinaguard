'use client';

import { LiveNetworkConsole } from '@/components/dashboard/live-network-console';


export default function DashboardPage() {
  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.12),_transparent_40%),linear-gradient(180deg,_#020617_0%,_#0f172a_52%,_#020617_100%)] text-white">
      <div className="w-full space-y-8">
                <LiveNetworkConsole />
      </div>
    </div>
  );
}
