'use client';

import { NetworkGraph } from '@/components/topology/network-graph';
import { TopologyErrorBoundary } from '@/components/topology/error-boundary';
import { Network } from 'lucide-react';

export default function TopologyPage() {
  return (
    <div className="flex flex-col h-screen bg-slate-900">
      {/* Header */}
      <div className="p-6 border-b border-slate-800">
        <h1 className="text-3xl font-bold text-white flex items-center gap-2">
          <Network className="w-8 h-8 text-blue-500" />
          Network Map
        </h1>
        <p className="text-slate-400 mt-2">
          Real-time visualization of sensors, access points, and connected devices
        </p>
      </div>

      {/* Graph Container with Error Boundary */}
      <div className="flex-1 overflow-hidden">
        <TopologyErrorBoundary>
          <NetworkGraph />
        </TopologyErrorBoundary>
      </div>
    </div>
  );
}
