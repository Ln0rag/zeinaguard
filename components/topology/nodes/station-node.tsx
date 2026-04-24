'use client';

import { Handle, Position } from 'reactflow';
import { Smartphone } from 'lucide-react';

interface StationNodeProps {
  data: any;
  isConnecting: boolean;
  selected: boolean;
}

export function StationNode({ data, selected }: StationNodeProps) {
  const isThreat = data.is_suspicious || data.threat_level === 'critical';
  
  return (
    <div
      className={`flex flex-col items-center gap-2 px-3 py-2 rounded-lg border-2 transition-all ${
        selected
          ? 'border-green-400 bg-green-900/30'
          : 'border-green-600 bg-green-900/20'
      } ${data.is_shared ? 'node-shared' : ''} ${isThreat ? 'node-threat' : ''}`}
    >
      <div className="flex items-center gap-2">
        <Smartphone className={`w-4 h-4 ${isThreat ? 'text-red-400 animate-pulse' : 'text-green-400'}`} />
        <span className="text-xs font-semibold text-white">{data.label}</span>
      </div>
      <span className="text-xs text-green-300">{data.device_type || 'Device'}</span>
      {data.is_shared && <span className="text-xs text-yellow-400 font-semibold">SHARED</span>}
      <Handle type="target" position={Position.Top} />
    </div>
  );
}
