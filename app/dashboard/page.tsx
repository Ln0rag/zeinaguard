'use client';

import { LiveNetworkConsole } from '@/components/dashboard/live-network-console';


export default function DashboardPage() {
  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.12),_transparent_40%),linear-gradient(180deg,_#020617_0%,_#0f172a_52%,_#020617_100%)] px-4 py-8 text-white sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-8">
        <div className="flex flex-col gap-3 border-b border-slate-800 pb-6">
          <div className="text-sm uppercase tracking-[0.35em] text-cyan-300">ZeinaGuard</div>
          <div>
            <h1 className="text-4xl font-semibold tracking-tight">Wireless Command Dashboard</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Backend-orchestrated real-time monitoring and sensor control with a single live pipeline.
            </p>
          </div>
        </div>
        <LiveNetworkConsole />
      </div>
    </div>
  );
}
