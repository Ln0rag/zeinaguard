'use client';

import { Handle, Position } from 'reactflow';
import { Radio } from 'lucide-react';

interface RouterNodeProps {
  data: any;
  isConnecting: boolean;
  selected: boolean;
}

export function RouterNode({ data, selected }: RouterNodeProps) {
  const isThreat = data.is_suspicious || data.threat_level === 'critical';
  
  return (
    <div
      className={`flex flex-col items-center gap-2 px-4 py-3 rounded-full border-2 transition-all ${
        selected
          ? 'border-purple-400 bg-purple-900/30'
          : 'border-purple-600 bg-purple-900/20'
      } ${data.is_shared ? 'node-shared' : ''} ${isThreat ? 'node-threat' : ''}`}
    >
      <div className="flex items-center gap-2">
        <Radio className={`w-5 h-5 ${isThreat ? 'text-red-400 animate-pulse' : 'text-purple-400'}`} />
        <span className="text-sm font-semibold text-white">{data.label}</span>
      </div>
      <span className="text-xs text-purple-300">{data.security || 'AP'}</span>
      {data.is_shared && <span className="text-xs text-yellow-400 font-semibold">SHARED</span>}
      <Handle type="both" position={Position.Top} />
      <Handle type="both" position={Position.Bottom} />
    </div>
  );
}
