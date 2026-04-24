'use client';

import { ThreatFeed } from '@/components/threats/threat-feed';

function ThreatsContent() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-950">
      {/* Header */}
      <div className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-6xl mx-auto px-4 py-4 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-white">ZeinaGuard</h1>
            <p className="text-sm text-slate-400">Real-Time Threat Feed</p>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-6xl mx-auto px-4 py-8">
        <ThreatFeed />
      </div>
    </div>
  );
}

export default function ThreatsPage() {
  return <ThreatsContent />;
}
