'use client';

import { Handle, Position } from 'reactflow';
import { Cpu } from 'lucide-react';

interface SensorNodeProps {
  data: any;
  isConnecting: boolean;
  selected: boolean;
}

export function SensorNode({ data, selected }: SensorNodeProps) {
  const isThreat = data.is_suspicious || data.threat_level === 'critical';
  
  return (
    <div
      className={`flex flex-col items-center gap-2 px-4 py-3 rounded-xl border-2 transition-all ${
        selected
          ? 'border-blue-400 bg-blue-900/30'
          : 'border-blue-600 bg-blue-900/20'
      } ${data.is_shared ? 'node-shared' : ''} ${isThreat ? 'node-threat' : ''}`}
    >
      <div className="flex items-center gap-2">
        <Cpu className={`w-5 h-5 ${isThreat ? 'text-red-400 animate-pulse' : 'text-blue-400'}`} />
        <span className="text-sm font-semibold text-white">{data.label}</span>
      </div>
      <span className="text-xs text-blue-300">{data.location || 'Sensor'}</span>
      {data.is_shared && <span className="text-xs text-yellow-400 font-semibold">SHARED</span>}
      <Handle type="both" position={Position.Bottom} />
    </div>
  );
}
