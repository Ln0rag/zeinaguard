'use client';

import { useEffect, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import ReactFlow, {
  Background,
  Controls,
  Edge,
  MiniMap,
  Node,
  Position,
  ReactFlowInstance,
  useEdgesState,
  useNodesState,
} from 'reactflow';
import { io, Socket } from 'socket.io-client';
import { Activity, Router, Shield, Smartphone, Wifi, WifiOff } from 'lucide-react';
import 'reactflow/dist/style.css';
import './topology.css';


type Classification = 'rogue' | 'suspicious' | 'legit';

interface ClientSnapshot {
  mac: string;
  type?: string | null;
}

interface NetworkSnapshotItem {
  sensor_id: number | null;
  bssid: string;
  ssid: string;
  signal: number | null;
  classification: Classification;
  last_seen: string;
  clients: ClientSnapshot[];
}

interface GraphNodeData {
  kind: 'network' | 'device';
  label: ReactNode;
  displayLabel: string;
  bssid?: string;
  mac?: string;
  ssid?: string;
  signal?: number | null;
  classification?: Classification;
  last_seen?: string;
  sensor_id?: number | null;
  clients?: ClientSnapshot[];
  deviceType?: string;
  clientCount?: number;
}


const SOCKET_URL = (
  process.env.NEXT_PUBLIC_SOCKET_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  process.env.NEXT_PUBLIC_BACKEND_URL ||
  'http://localhost:5000'
).replace(/\/$/, '');

const UI_REFRESH_INTERVAL_MS = 60_000;


function normalizeClassification(value: unknown): Classification {
  const classification = String(value || 'legit').trim().toLowerCase();
  if (classification === 'rogue' || classification === 'suspicious') {
    return classification;
  }
  return 'legit';
}


function normalizeLastSeen(value: unknown): string {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const timestamp = value > 1_000_000_000_000 ? value : value * 1000;
    return new Date(timestamp).toISOString();
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^\d+$/.test(trimmed)) {
      const numericValue = Number(trimmed);
      const timestamp = numericValue > 1_000_000_000_000 ? numericValue : numericValue * 1000;
      return new Date(timestamp).toISOString();
    }

    const parsed = new Date(trimmed);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
  }

  return new Date().toISOString();
}


function normalizeClient(client: ClientSnapshot): ClientSnapshot | null {
  const mac = String(client?.mac || '').trim().toUpperCase();
  if (!mac) {
    return null;
  }

  return {
    mac,
    type: String(client?.type || 'device').trim().toLowerCase() || 'device',
  };
}


function normalizeSnapshot(payload: unknown): NetworkSnapshotItem[] {
  const rawSnapshot = Array.isArray(payload)
    ? payload
    : payload && typeof payload === 'object' && Array.isArray((payload as { data?: unknown[] }).data)
      ? (payload as { data: unknown[] }).data
      : null;

  if (!rawSnapshot) {
    return [];
  }

  return rawSnapshot
    .map((item) => {
      if (!item || typeof item !== 'object') {
        return null;
      }

      const network = item as Record<string, unknown>;
      const bssid = String(network.bssid || '').trim().toUpperCase();
      if (!bssid) {
        return null;
      }

      const clients = Array.isArray(network.clients)
        ? network.clients
            .map((client) => normalizeClient(client as ClientSnapshot))
            .filter((client): client is ClientSnapshot => Boolean(client))
            .sort((left, right) => left.mac.localeCompare(right.mac))
        : [];

      return {
        sensor_id: typeof network.sensor_id === 'number' ? network.sensor_id : Number(network.sensor_id || 0) || null,
        bssid,
        ssid: String(network.ssid || 'Hidden').trim() || 'Hidden',
        signal: network.signal == null ? null : Number(network.signal),
        classification: normalizeClassification(network.classification),
        last_seen: normalizeLastSeen(network.last_seen ?? network.timestamp),
        clients,
      };
    })
    .filter((network): network is NetworkSnapshotItem => Boolean(network))
    .sort((left, right) => left.bssid.localeCompare(right.bssid));
}


function getNodeStyle(classification: Classification) {
  switch (classification) {
    case 'rogue':
      return {
        border: '1.5px solid rgba(239, 68, 68, 0.95)',
        boxShadow: '0 0 18px rgba(239, 68, 68, 0.30)',
      };
    case 'suspicious':
      return {
        border: '1.5px solid rgba(249, 115, 22, 0.95)',
        boxShadow: '0 0 18px rgba(249, 115, 22, 0.24)',
      };
    default:
      return {
        border: '1.5px solid rgba(34, 197, 94, 0.90)',
        boxShadow: '0 0 18px rgba(34, 197, 94, 0.18)',
      };
  }
}


function getClassificationTextColor(classification: Classification) {
  switch (classification) {
    case 'rogue':
      return 'text-red-300';
    case 'suspicious':
      return 'text-orange-300';
    default:
      return 'text-emerald-300';
  }
}


function getClassificationChip(classification: Classification) {
  switch (classification) {
    case 'rogue':
      return 'bg-red-950/80 text-red-200 border border-red-700/60';
    case 'suspicious':
      return 'bg-orange-950/80 text-orange-200 border border-orange-700/60';
    default:
      return 'bg-emerald-950/80 text-emerald-200 border border-emerald-700/60';
  }
}


function getEdgeColor(classification: Classification) {
  switch (classification) {
    case 'rogue':
      return 'rgba(239, 68, 68, 0.65)';
    case 'suspicious':
      return 'rgba(249, 115, 22, 0.58)';
    default:
      return 'rgba(34, 197, 94, 0.45)';
  }
}


function relativeLastSeen(lastSeen?: string) {
  if (!lastSeen) {
    return 'unknown';
  }

  const deltaSeconds = Math.max(0, Math.floor((Date.now() - new Date(lastSeen).getTime()) / 1000));
  if (deltaSeconds < 2) {
    return 'now';
  }
  if (deltaSeconds < 60) {
    return `${deltaSeconds}s ago`;
  }
  if (deltaSeconds < 3600) {
    return `${Math.floor(deltaSeconds / 60)}m ago`;
  }
  return `${Math.floor(deltaSeconds / 3600)}h ago`;
}


function buildSnapshotSignature(snapshot: NetworkSnapshotItem[]) {
  return snapshot
    .map((network) => [
      network.bssid,
      network.ssid,
      network.signal ?? 'na',
      network.classification,
      network.last_seen,
      network.clients.map((client) => `${client.mac}:${client.type || 'device'}`).join(','),
    ].join('|'))
    .join('||');
}


function buildNetworkLabel(network: NetworkSnapshotItem): ReactNode {
  const clientCount = network.clients.length;
  const classification = normalizeClassification(network.classification);

  return (
    <div className="space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-slate-50">{network.ssid || 'Hidden'}</div>
          <div className="truncate font-mono text-[10px] text-slate-400">{network.bssid}</div>
        </div>
        <span className={`shrink-0 rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.2em] ${getClassificationChip(classification)}`}>
          {classification}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-2 text-[10px] uppercase tracking-[0.18em] text-slate-400">
        <div className="rounded-xl bg-slate-900/70 px-2 py-2">
          <div>Signal</div>
          <div className="mt-1 text-xs font-semibold text-slate-100">{network.signal ?? 'N/A'} dBm</div>
        </div>
        <div className="rounded-xl bg-slate-900/70 px-2 py-2">
          <div>Class</div>
          <div className={`mt-1 text-xs font-semibold uppercase ${getClassificationTextColor(classification)}`}>{classification}</div>
        </div>
        <div className="rounded-xl bg-slate-900/70 px-2 py-2">
          <div>Clients</div>
          <div className="mt-1 text-xs font-semibold text-slate-100">{clientCount}</div>
        </div>
      </div>
    </div>
  );
}


function buildDeviceLabel(client: ClientSnapshot): ReactNode {
  return (
    <div className="space-y-2">
      <div className="truncate font-mono text-[11px] font-medium text-slate-100">{client.mac}</div>
      <div className="flex items-center justify-between gap-2">
        <span className="rounded-full border border-slate-700 bg-slate-800/90 px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-300">
          Device
        </span>
        <span className="truncate text-[10px] uppercase tracking-[0.18em] text-slate-500">{client.type || 'device'}</span>
      </div>
    </div>
  );
}


function buildGraph(snapshot: NetworkSnapshotItem[]): { nodes: Node<GraphNodeData>[]; edges: Edge[] } {
  const nodes: Node<GraphNodeData>[] = [];
  const edges: Edge[] = [];

  const networksPerRow = 3;
  const networkSpacingX = 320;
  const networkSpacingY = 320;
  const networkStartX = 80;
  const networkStartY = 60;

  snapshot.forEach((network, index) => {
    const classification = normalizeClassification(network.classification);
    const column = index % networksPerRow;
    const row = Math.floor(index / networksPerRow);
    const networkX = networkStartX + (column * networkSpacingX);
    const networkY = networkStartY + (row * networkSpacingY);

    nodes.push({
      id: network.bssid,
      position: { x: networkX, y: networkY },
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top,
      draggable: false,
      selectable: true,
      data: {
        kind: 'network',
        label: buildNetworkLabel(network),
        displayLabel: network.ssid || 'Hidden',
        bssid: network.bssid,
        ssid: network.ssid || 'Hidden',
        signal: network.signal,
        classification,
        last_seen: network.last_seen,
        sensor_id: network.sensor_id,
        clients: network.clients,
        clientCount: network.clients.length,
      },
      style: {
        width: 240,
        minHeight: 122,
        background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.98) 0%, rgba(2, 6, 23, 0.98) 100%)',
        color: '#f8fafc',
        borderRadius: 22,
        padding: '14px',
        fontSize: 12,
        textAlign: 'left',
        ...getNodeStyle(classification),
      },
    });

    const clients = [...network.clients].sort((left, right) => left.mac.localeCompare(right.mac));
    const radius = clients.length > 3 ? 165 : 145;
    const centerX = networkX + 120;
    const centerY = networkY + 61;
    const angleStep = clients.length > 0 ? (Math.PI * 2) / clients.length : 0;

    clients.forEach((client, clientIndex) => {
      const angle = (angleStep * clientIndex) - (Math.PI / 2);
      const clientX = centerX + (Math.cos(angle) * radius) - 95;
      const clientY = centerY + (Math.sin(angle) * radius) - 32;
      const clientNodeId = `${network.bssid}::${client.mac}`;

      nodes.push({
        id: clientNodeId,
        position: { x: clientX, y: clientY },
        draggable: false,
        selectable: true,
        data: {
          kind: 'device',
          label: buildDeviceLabel(client),
          displayLabel: client.mac,
          mac: client.mac,
          deviceType: client.type || 'device',
        },
        style: {
          width: 190,
          minHeight: 64,
          background: 'rgba(15, 23, 42, 0.96)',
          color: '#cbd5e1',
          border: '1px solid rgba(51, 65, 85, 0.92)',
          borderRadius: 18,
          padding: '10px 12px',
          fontSize: 11,
          textAlign: 'left',
          boxShadow: '0 10px 30px rgba(2, 6, 23, 0.30)',
        },
      });

      edges.push({
        id: `${network.bssid}-${client.mac}`,
        source: network.bssid,
        target: clientNodeId,
        type: 'smoothstep',
        animated: false,
        style: {
          stroke: getEdgeColor(classification),
          strokeWidth: 1.15,
        },
      });
    });
  });

  return { nodes, edges };
}


export function NetworkGraph() {
  const [nodes, setNodes, onNodesChange] = useNodesState<GraphNodeData>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNodeData | null>(null);
  const [lastUiRefresh, setLastUiRefresh] = useState<string | null>(null);

  const socketRef = useRef<Socket | null>(null);
  const latestSnapshotRef = useRef<NetworkSnapshotItem[] | null>(null);
  const hasAppliedInitialSnapshotRef = useRef(false);
  const appliedSignatureRef = useRef('');
  const flowRef = useRef<ReactFlowInstance | null>(null);
  const hasFitInitialViewRef = useRef(false);

  const applySnapshotToGraph = (snapshot: NetworkSnapshotItem[]) => {
    const signature = buildSnapshotSignature(snapshot);
    if (signature === appliedSignatureRef.current) {
      return;
    }

    const nextGraph = buildGraph(snapshot);
    setNodes(nextGraph.nodes);
    setEdges(nextGraph.edges);
    setLoading(false);
    setError(null);
    appliedSignatureRef.current = signature;
    setLastUiRefresh(new Date().toISOString());

    if (!hasFitInitialViewRef.current) {
      window.requestAnimationFrame(() => {
        flowRef.current?.fitView({ padding: 0.18, duration: 300 });
      });
      hasFitInitialViewRef.current = true;
    }
  };

  useEffect(() => {
    const socket = io(SOCKET_URL, {
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity,
      timeout: 10000,
      transports: ['websocket', 'polling'],
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      setConnected(true);
      setError(null);
    });

    socket.on('disconnect', () => {
      setConnected(false);
    });

    socket.on('connect_error', (connectError: Error) => {
      setConnected(false);
      setLoading(false);
      setError(connectError.message || 'Unable to connect to realtime backend');
    });

    socket.on('networks_snapshot', (payload: unknown) => {
      const snapshot = normalizeSnapshot(payload);
      latestSnapshotRef.current = snapshot;

      if (!hasAppliedInitialSnapshotRef.current) {
        applySnapshotToGraph(snapshot);
        hasAppliedInitialSnapshotRef.current = true;
      }
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [setEdges, setNodes]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      if (!latestSnapshotRef.current) {
        return;
      }

      applySnapshotToGraph(latestSnapshotRef.current);
    }, UI_REFRESH_INTERVAL_MS);

    return () => {
      window.clearInterval(interval);
    };
  }, [setEdges, setNodes]);

  const handleNodeClick = (_event: ReactMouseEvent, node: Node<GraphNodeData>) => {
    setSelectedNode(node.data);
  };

  if (loading) {
    return (
      <div className="flex h-full w-full items-center justify-center bg-slate-950">
        <div className="text-center">
          <div className="mx-auto mb-4 h-12 w-12 rounded-full border-4 border-cyan-500 border-t-transparent animate-spin" />
          <p className="text-slate-300">Waiting for buffered network snapshots...</p>
        </div>
      </div>
    );
  }

  if (error && nodes.length === 0) {
    return (
      <div className="flex h-full w-full items-center justify-center bg-slate-950">
        <div className="max-w-md rounded-2xl border border-red-800 bg-slate-900 p-8 text-center">
          <div className="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-full border border-red-700 bg-red-950/40">
            <WifiOff className="h-7 w-7 text-red-400" />
          </div>
          <h2 className="mb-2 text-2xl font-semibold text-white">Realtime connection failed</h2>
          <p className="mb-4 text-sm text-slate-300">{error}</p>
          <p className="text-xs text-slate-500">Socket target: {SOCKET_URL}</p>
        </div>
      </div>
    );
  }

  const networkNodesCount = nodes.filter((node) => node.data.kind === 'network').length;
  const deviceNodesCount = nodes.filter((node) => node.data.kind === 'device').length;

  return (
    <div className="flex h-full w-full bg-slate-950">
      <div className="relative flex-1">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          onInit={(instance) => {
            flowRef.current = instance;
          }}
          fitView
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          panOnDrag
          zoomOnScroll
          defaultEdgeOptions={{
            type: 'smoothstep',
            animated: false,
          }}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1e293b" gap={22} />
          <MiniMap
            pannable
            zoomable
            nodeColor={(node) => {
              if (node.data?.kind === 'device') {
                return '#475569';
              }
              return getEdgeColor((node.data?.classification || 'legit') as Classification);
            }}
            maskColor="rgba(2, 6, 23, 0.48)"
            style={{ backgroundColor: '#020617', border: '1px solid #1e293b' }}
          />
          <Controls />
        </ReactFlow>

        <div className="absolute left-4 top-4 flex items-center gap-3 rounded-full border border-slate-700 bg-slate-950/90 px-4 py-2 text-sm text-slate-200 shadow-lg backdrop-blur">
          {connected ? <Wifi className="h-4 w-4 text-emerald-400" /> : <WifiOff className="h-4 w-4 text-red-400" />}
          <span>{connected ? 'Socket Connected' : 'Socket Reconnecting'}</span>
          <span className="text-slate-500">|</span>
          <span>{networkNodesCount} networks</span>
          <span>{deviceNodesCount} devices</span>
          <span className="text-slate-500">|</span>
          <span>UI refresh: 60s</span>
        </div>

        <div className="absolute bottom-4 left-4 rounded-2xl border border-slate-800 bg-slate-950/90 px-4 py-3 text-xs text-slate-300 shadow-lg backdrop-blur">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            <span>Stable buffered rendering from live Socket.IO snapshots</span>
          </div>
          {lastUiRefresh && (
            <div className="mt-2 text-slate-500">Last UI refresh: {relativeLastSeen(lastUiRefresh)}</div>
          )}
        </div>
      </div>

      <aside className="h-full w-[360px] border-l border-slate-800 bg-slate-900/90 p-6">
        {selectedNode ? (
          <div className="space-y-5">
            <div>
              <div className="mb-2 flex items-center gap-2">
                {selectedNode.kind === 'network' ? (
                  <Router className="h-5 w-5 text-cyan-400" />
                ) : (
                  <Smartphone className="h-5 w-5 text-slate-400" />
                )}
                <h3 className="text-lg font-semibold text-white">
                  {selectedNode.kind === 'network' ? 'Network Details' : 'Device Details'}
                </h3>
              </div>
              <p className="text-sm text-slate-400">
                {selectedNode.kind === 'network'
                  ? 'Live snapshot metadata from the backend'
                  : 'Observed client device in the current buffered graph'}
              </p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
              <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Label</div>
              <div className="mt-2 text-base font-semibold text-white">{selectedNode.displayLabel}</div>
            </div>

            {selectedNode.kind === 'network' ? (
              <>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">SSID</div>
                    <div className="mt-2 text-sm text-slate-200">{selectedNode.ssid || 'Hidden'}</div>
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">BSSID</div>
                    <div className="mt-2 break-all font-mono text-sm text-slate-200">{selectedNode.bssid}</div>
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Signal</div>
                    <div className="mt-2 text-sm text-slate-200">{selectedNode.signal ?? 'N/A'} dBm</div>
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Classification</div>
                    <div className={`mt-2 text-sm font-semibold uppercase ${getClassificationTextColor(selectedNode.classification || 'legit')}`}>
                      {selectedNode.classification}
                    </div>
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Last Seen</div>
                    <div className="mt-2 text-sm text-slate-200">{relativeLastSeen(selectedNode.last_seen)}</div>
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Clients Count</div>
                    <div className="mt-2 text-sm text-slate-200">{selectedNode.clientCount || selectedNode.clients?.length || 0}</div>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Clients</div>
                    <div className="text-xs text-slate-400">{selectedNode.clients?.length || 0} total</div>
                  </div>
                  <div className="space-y-2">
                    {(selectedNode.clients || []).length > 0 ? (
                      (selectedNode.clients || []).map((client) => (
                        <div key={client.mac} className="rounded-xl border border-slate-800 bg-slate-900 px-3 py-2">
                          <div className="font-mono text-xs text-slate-200">{client.mac}</div>
                          <div className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-500">{client.type || 'device'}</div>
                        </div>
                      ))
                    ) : (
                      <div className="text-sm text-slate-500">No client devices reported for this network.</div>
                    )}
                  </div>
                </div>
              </>
            ) : (
              <>
                <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                  <div className="text-xs uppercase tracking-[0.2em] text-slate-500">MAC Address</div>
                  <div className="mt-2 break-all font-mono text-sm text-slate-200">{selectedNode.mac}</div>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                  <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Type</div>
                  <div className="mt-2 text-sm text-slate-200">{selectedNode.deviceType || 'device'}</div>
                </div>
              </>
            )}
          </div>
        ) : (
          <div className="flex h-full items-center justify-center rounded-3xl border border-dashed border-slate-800 bg-slate-950 p-6 text-center text-sm text-slate-500">
            Click a node to inspect its details.
          </div>
        )}
      </aside>
    </div>
  );
}
