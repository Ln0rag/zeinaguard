'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, AlertTriangle, Radio, Wifi, WifiOff, Zap } from 'lucide-react';
import { toast } from 'sonner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  useSocket,
  type AttackAckEvent,
  type AttackCommandAckEvent,
  type AttackCommandEvent,
  type LiveNetworkEvent,
  type NetworkRemovedEvent,
  type SensorStatusEvent,
} from '@/hooks/use-socket';


type ClassificationFilter = 'ALL' | 'ROGUE' | 'SUSPICIOUS' | 'LEGIT';

interface ActivityItem {
  id: string;
  type: 'threat' | 'command' | 'status' | 'ack';
  title: string;
  detail: string;
  timestamp: string;
}


function estimateDistance(signal: number | null) {
  if (signal === null || signal === undefined) {
    return 'Unknown';
  }
  if (signal >= -45) {
    return '~1m';
  }
  if (signal >= -55) {
    return '~3m';
  }
  if (signal >= -65) {
    return '~7m';
  }
  if (signal >= -75) {
    return '~15m';
  }
  return '20m+';
}


function trendFromHistory(history: number[]) {
  if (history.length < 2) {
    return 'Stable';
  }
  const first = history[0];
  const last = history[history.length - 1];
  if (last > first) {
    return 'Closer';
  }
  if (last < first) {
    return 'Away';
  }
  return 'Stable';
}


function relativeLastSeen(timestamp: string | undefined) {
  if (!timestamp) {
    return 'unknown';
  }

  const seen = new Date(timestamp).getTime();
  const deltaSeconds = Math.max(0, Math.floor((Date.now() - seen) / 1000));
  if (deltaSeconds < 2) {
    return 'now';
  }
  if (deltaSeconds < 60) {
    return `${deltaSeconds}s ago`;
  }
  const deltaMinutes = Math.floor(deltaSeconds / 60);
  if (deltaMinutes < 60) {
    return `${deltaMinutes}m ago`;
  }
  return `${Math.floor(deltaMinutes / 60)}h ago`;
}


function signalBarWidth(signal: number | null) {
  if (signal === null || signal === undefined) {
    return 0;
  }
  return Math.max(0, Math.min(100, ((signal + 100) / 70) * 100));
}


function classificationClasses(classification: LiveNetworkEvent['classification']) {
  if (classification === 'ROGUE') {
    return 'bg-red-950 text-red-100 border border-red-700';
  }
  if (classification === 'SUSPICIOUS') {
    return 'bg-amber-950 text-amber-100 border border-amber-700';
  }
  return 'bg-emerald-950 text-emerald-100 border border-emerald-700';
}


function normalizeNetwork(network: LiveNetworkEvent): LiveNetworkEvent {
  return {
    ...network,
    bssid: String(network.bssid || '').toUpperCase(),
    classification: network.classification ?? 'LEGIT',
    last_seen: network.last_seen || network.timestamp || new Date().toISOString(),
  };
}


export function LiveNetworkConsole() {
  const [networks, setNetworks] = useState<LiveNetworkEvent[]>([]);
  const [sensorStatuses, setSensorStatuses] = useState<SensorStatusEvent[]>([]);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [hasNetworkSnapshot, setHasNetworkSnapshot] = useState(false);
  const [hasSensorSnapshot, setHasSensorSnapshot] = useState(false);
  const [filter, setFilter] = useState<ClassificationFilter>('ALL');
  const [huntTarget, setHuntTarget] = useState('');
  const [attackState, setAttackState] = useState<string | null>(null);

  const signalHistoryRef = useRef<Record<string, number[]>>({});

  const apiBase = (
    process.env.NEXT_PUBLIC_API_URL ||
    process.env.NEXT_PUBLIC_BACKEND_URL ||
    'http://localhost:5000'
  ).replace(/\/$/, '');

  const appendActivity = (item: ActivityItem) => {
    setActivity((current) => [item, ...current].slice(0, 20));
  };

  const trackSignalHistory = (snapshot: LiveNetworkEvent[]) => {
    for (const network of snapshot) {
      if (network.signal === null || network.signal === undefined) {
        continue;
      }
      const history = signalHistoryRef.current[network.bssid] ?? [];
      signalHistoryRef.current[network.bssid] = [...history.slice(-7), network.signal];
    }
  };

  const { isConnected, sendAttackCommand } = useSocket({
    onNetworkSnapshot: (event) => {
      const nextNetworks = (event.data || []).map(normalizeNetwork);
      trackSignalHistory(nextNetworks);
      setNetworks(nextNetworks);
      setHasNetworkSnapshot(true);
    },
    onSensorSnapshot: (event) => {
      setSensorStatuses(
        (event.data || []).map((sensor) => ({
          ...sensor,
          last_seen: sensor.last_seen || sensor.last_heartbeat,
          last_heartbeat: sensor.last_heartbeat || sensor.last_seen,
        })),
      );
      setHasSensorSnapshot(true);
    },
    onSensorStatusUpdate: (event) => {
      const sensor = event.data;
      appendActivity({
        id: `status-${sensor.sensor_id}-${sensor.last_seen}`,
        type: 'status',
        title: `Sensor #${sensor.sensor_id} ${sensor.status}`,
        detail: sensor.message || sensor.interface || 'Status updated',
        timestamp: sensor.last_seen || sensor.last_heartbeat,
      });
    },
    onNetworkRemoved: (event) => {
      const normalizedBssid = event.bssid.toUpperCase();
      setNetworks((current) => current.filter((network) => network.bssid !== normalizedBssid));
      appendActivity({
        id: `removed-${normalizedBssid}-${Date.now()}`,
        type: 'status',
        title: 'Network removed',
        detail: normalizedBssid,
        timestamp: new Date().toISOString(),
      });
    },
    onThreatDetected: (event) => {
      const network = normalizeNetwork(event);
      appendActivity({
        id: `threat-${network.bssid}-${network.last_seen}`,
        type: 'threat',
        title: `${network.classification} network detected`,
        detail: `${network.ssid || 'Hidden'} | ${network.bssid}`,
        timestamp: network.last_seen,
      });
    },
    onAttackCommand: (event: AttackCommandEvent) => {
      appendActivity({
        id: `command-${event.sensor_id}-${event.bssid}-${event.timestamp || Date.now()}`,
        type: 'command',
        title: `Command ${event.status || 'sent'}`,
        detail: `deauth -> ${event.bssid}`,
        timestamp: event.timestamp || new Date().toISOString(),
      });
      setAttackState(`Dispatching deauth command for ${event.bssid} via sensor #${event.sensor_id}`);
    },
    onAttackCommandAck: (event: AttackCommandAckEvent) => {
      const target = event.bssid || 'unknown target';
      const detailParts = [
        event.sensor_id ? `Sensor #${event.sensor_id}` : null,
        target,
        event.message || null,
      ].filter(Boolean);

      appendActivity({
        id: `dispatch-${event.sensor_id || 'unknown'}-${target}-${event.timestamp}`,
        type: 'command',
        title: event.status === 'ok' ? 'Attack dispatch confirmed' : 'Attack dispatch rejected',
        detail: detailParts.join(' | '),
        timestamp: event.timestamp,
      });

      if (event.status === 'ok') {
        setAttackState(`Dispatch confirmed for ${target}`);
      } else {
        setAttackState(event.message || `Attack dispatch rejected for ${target}`);
        toast.error('Attack dispatch rejected', {
          description: event.message || `Backend rejected the command for ${target}`,
        });
      }
    },
    onAttackAck: (event: AttackAckEvent) => {
      appendActivity({
        id: `ack-${event.sensor_id}-${event.bssid}-${event.timestamp}`,
        type: 'ack',
        title: `Attack ${event.status}`,
        detail: `Sensor #${event.sensor_id} | ${event.bssid}${event.message ? ` | ${event.message}` : ''}`,
        timestamp: event.timestamp,
      });
      setAttackState(`Attack ${event.status} for ${event.bssid}`);
      if (event.status === 'executed') {
        toast.success('Attack acknowledged', {
          description: event.message || `Sensor #${event.sensor_id} confirmed ${event.bssid}`,
        });
      } else {
        toast.error('Attack failed', {
          description: event.message || `Sensor #${event.sensor_id} failed ${event.bssid}`,
        });
      }
    },
  });

  const loading = !hasNetworkSnapshot;

  useEffect(() => {
    let cancelled = false;

    const refreshActiveNetworks = async () => {
      try {
        const response = await fetch(`${apiBase}/networks/active`, {
          cache: 'no-store',
        });
        if (!response.ok) {
          throw new Error(`Active network request failed (${response.status})`);
        }

        const payload = await response.json();
        if (cancelled) {
          return;
        }

        const nextNetworks = Array.isArray(payload.networks)
          ? payload.networks.map((network: LiveNetworkEvent) => normalizeNetwork(network))
          : [];
        trackSignalHistory(nextNetworks);
        setNetworks(nextNetworks);
        setHasNetworkSnapshot(true);
      } catch (error) {
        console.error('[ACTIVE NETWORK POLL] failed', error);
      }
    };

    refreshActiveNetworks();

    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  const networkList = useMemo(() => {
    const filtered = filter === 'ALL'
      ? networks
      : networks.filter((network) => network.classification === filter);

    return [...filtered].sort((left, right) => {
      const leftTime = new Date(left.last_seen).getTime();
      const rightTime = new Date(right.last_seen).getTime();
      return rightTime - leftTime;
    });
  }, [filter, networks]);

  const huntedNetwork = useMemo(() => {
    const normalized = huntTarget.trim().toUpperCase();
    if (!normalized) {
      return null;
    }
    return networks.find((network) => network.bssid === normalized) || null;
  }, [huntTarget, networks]);

  const rogueCount = networks.filter((network) => network.classification === 'ROGUE').length;
  const suspiciousCount = networks.filter((network) => network.classification === 'SUSPICIOUS').length;
  const legitCount = networks.filter((network) => network.classification === 'LEGIT').length;
  const onlineSensors = sensorStatuses.filter((sensor) => sensor.status !== 'offline').length;

  // Debug interface detection
  const detectedInterfaces = sensorStatuses.length > 0 
    ? sensorStatuses.map(sensor => sensor.interface || 'Unknown').filter((iface, index, arr) => arr.indexOf(iface) === index)
    : ['wlan0', 'wlan1']; // Fallback interfaces for testing

  const handleAttack = (network: LiveNetworkEvent) => {
    try {
      sendAttackCommand({
        sensor_id: network.sensor_id,
        bssid: network.bssid,
      });
      setAttackState(`Dispatching deauth command for ${network.bssid} via sensor #${network.sensor_id}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to send attack command';
      setAttackState(message);
      toast.error('Attack dispatch failed', { description: message });
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-2">
            <CardDescription className="text-slate-400">Live Networks</CardDescription>
            <CardTitle className="text-3xl text-white">{networks.length}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-slate-400">Snapshot replaces the entire live network table every second</CardContent>
        </Card>
        <Card className="bg-red-950/50 border-red-900">
          <CardHeader className="pb-2">
            <CardDescription className="text-red-200">Rogue</CardDescription>
            <CardTitle className="text-3xl text-red-50">{rogueCount}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-red-200">Immediate response candidates</CardContent>
        </Card>
        <Card className="bg-amber-950/50 border-amber-900">
          <CardHeader className="pb-2">
            <CardDescription className="text-amber-200">Suspicious</CardDescription>
            <CardTitle className="text-3xl text-amber-50">{suspiciousCount}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-amber-200">Watchlist targets</CardContent>
        </Card>
        <Card className="bg-emerald-950/50 border-emerald-900">
          <CardHeader className="pb-2">
            <CardDescription className="text-emerald-200">Sensors Online</CardDescription>
            <CardTitle className="text-3xl text-emerald-50">{onlineSensors}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-emerald-200">{legitCount} legit networks in scope</CardContent>
        </Card>
      </div>

      <div className={`flex items-center justify-between rounded-xl border px-4 py-3 ${
        isConnected() ? 'border-emerald-700 bg-emerald-950/40 text-emerald-100' : 'border-red-700 bg-red-950/40 text-red-100'
      }`}>
        <div className="flex items-center gap-3">
          {isConnected() ? <Wifi className="h-4 w-4" /> : <WifiOff className="h-4 w-4" />}
          <span className="font-medium">{isConnected() ? 'Realtime pipeline connected' : 'Realtime pipeline reconnecting'}</span>
        </div>
        <span className="text-sm opacity-80">Sensor {'->'} Backend {'->'} Dashboard</span>
      </div>

      {attackState && (
        <Card className="border-slate-700 bg-slate-900">
          <CardContent className="pt-6 text-sm text-slate-200">{attackState}</CardContent>
        </Card>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <CardTitle className="text-white">Live Network Table</CardTitle>
                <CardDescription className="text-slate-400">
                  Real-time state rendered directly from backend snapshots
                </CardDescription>
              </div>
              <div className="flex flex-wrap gap-2">
                {(['ALL', 'ROGUE', 'SUSPICIOUS', 'LEGIT'] as ClassificationFilter[]).map((value) => (
                  <Button
                    key={value}
                    type="button"
                    variant={filter === value ? 'default' : 'outline'}
                    className={filter === value ? 'bg-cyan-600 text-white hover:bg-cyan-500' : 'border-slate-700 bg-slate-950 text-slate-200 hover:bg-slate-800'}
                    onClick={() => setFilter(value)}
                  >
                    {value}
                  </Button>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex h-64 items-center justify-center text-slate-400">
                <Activity className="mr-2 h-5 w-5 animate-spin" />
                Waiting for realtime snapshots...
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm text-slate-200">
                  <thead className="text-left text-xs uppercase tracking-wide text-slate-400">
                    <tr>
                      <th className="px-3 py-3">SSID</th>
                      <th className="px-3 py-3">BSSID</th>
                      <th className="px-3 py-3">Signal</th>
                      <th className="px-3 py-3">Class</th>
                      <th className="px-3 py-3">Last Seen</th>
                      <th className="px-3 py-3">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {networkList.map((network) => (
                      <tr key={network.bssid} className="border-t border-slate-800">
                        <td className="px-3 py-3 font-medium text-white">{network.ssid || 'Hidden'}</td>
                        <td className="px-3 py-3 font-mono text-xs text-slate-300">{network.bssid}</td>
                        <td className="px-3 py-3">{network.signal ?? 'N/A'} dBm</td>
                        <td className="px-3 py-3">
                          <span className={`rounded-full px-2 py-1 text-xs font-semibold ${classificationClasses(network.classification)}`}>
                            {network.classification}
                          </span>
                        </td>
                        <td className="px-3 py-3 text-slate-300">{relativeLastSeen(network.last_seen)}</td>
                        <td className="px-3 py-3">
                          <Button
                            type="button"
                            size="sm"
                            className="bg-red-600 text-white hover:bg-red-500"
                            onClick={() => handleAttack(network)}
                          >
                            Attack
                          </Button>
                        </td>
                      </tr>
                    ))}
                    {networkList.length === 0 && (
                      <tr>
                        <td className="px-3 py-10 text-center text-slate-500" colSpan={6}>
                          No active networks in the current snapshot
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Rogue Hunt Mode</CardTitle>
              <CardDescription className="text-slate-400">
                Track one BSSID and watch signal direction in real time
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <input
                value={huntTarget}
                onChange={(event) => setHuntTarget(event.target.value)}
                placeholder="AA:BB:CC:DD:EE:FF"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white outline-none placeholder:text-slate-500"
              />
              {huntedNetwork ? (
                <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-sm text-slate-400">Signal</div>
                      <div className="text-2xl font-semibold text-white">{huntedNetwork.signal ?? 'N/A'} dBm</div>
                    </div>
                    <div className={`rounded-full px-2 py-1 text-xs font-semibold ${classificationClasses(huntedNetwork.classification)}`}>
                      {huntedNetwork.classification}
                    </div>
                  </div>
                  <div>
                    <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
                      <span>Radar meter</span>
                      <span>{signalBarWidth(huntedNetwork.signal).toFixed(0)}%</span>
                    </div>
                    <div className="h-3 overflow-hidden rounded-full bg-slate-800">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-cyan-500 via-emerald-400 to-lime-300"
                        style={{ width: `${signalBarWidth(huntedNetwork.signal)}%` }}
                      />
                    </div>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Distance</div>
                      <div className="mt-1 text-sm text-white">{estimateDistance(huntedNetwork.signal)}</div>
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500">Trend</div>
                      <div className="mt-1 text-sm text-white">
                        {trendFromHistory(signalHistoryRef.current[huntedNetwork.bssid] || [])}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="rounded-xl border border-dashed border-slate-700 p-4 text-sm text-slate-400">
                  Enter a BSSID from the live table to start hunting.
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Sensor Status</CardTitle>
              <CardDescription className="text-slate-400">Live CPU, memory, and uptime from each sensor</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {sensorStatuses.length === 0 ? (
                <div className="text-sm text-slate-500">Waiting for sensor snapshot...</div>
              ) : (
                [...sensorStatuses]
                  .sort((left, right) => left.sensor_id - right.sensor_id)
                  .map((sensor) => (
                    <div key={sensor.sensor_id} className="rounded-xl border border-slate-800 bg-slate-950 p-3">
                      <div className="flex items-center justify-between">
                        <div className="font-medium text-white">Sensor #{sensor.sensor_id}</div>
                        <div className={`rounded-full px-2 py-1 text-xs ${
                          sensor.status === 'offline' ? 'bg-red-950 text-red-100' : 'bg-emerald-950 text-emerald-100'
                        }`}>
                          {sensor.status}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-slate-400">
                        {sensor.interface || 'Unknown interface'} | heartbeat {relativeLastSeen(sensor.last_heartbeat)}
                      </div>
                      <div className="mt-3 grid grid-cols-3 gap-2 text-xs text-slate-300">
                        <div className="rounded-lg border border-slate-800 bg-slate-900 px-2 py-2">
                          CPU {Number(sensor.cpu ?? 0).toFixed(1)}%
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-900 px-2 py-2">
                          MEM {Number(sensor.memory ?? 0).toFixed(1)}%
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-900 px-2 py-2">
                          UP {sensor.uptime}s
                        </div>
                      </div>
                    </div>
                  ))
              )}
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Activity Stream</CardTitle>
              <CardDescription className="text-slate-400">Threats, commands, acknowledgments, and sensor state changes</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {activity.length === 0 ? (
                <div className="text-sm text-slate-500">No live activity yet.</div>
              ) : (
                activity.map((item) => (
                  <div key={item.id} className="rounded-xl border border-slate-800 bg-slate-950 p-3">
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5">
                        {item.type === 'threat' && <AlertTriangle className="h-4 w-4 text-red-400" />}
                        {item.type === 'command' && <Zap className="h-4 w-4 text-cyan-400" />}
                        {item.type === 'status' && <Radio className="h-4 w-4 text-emerald-400" />}
                        {item.type === 'ack' && <Activity className="h-4 w-4 text-lime-400" />}
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-white">{item.title}</div>
                        <div className="text-sm text-slate-400">{item.detail}</div>
                        <div className="mt-1 text-xs text-slate-500">{relativeLastSeen(item.timestamp)}</div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
