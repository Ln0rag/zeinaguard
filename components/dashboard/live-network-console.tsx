'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useTheme } from 'next-themes';
import { Activity, AlertTriangle, ArrowUpDown, Radio, Wifi, WifiOff, Zap, Server, Shield, Target, Clock, Search, X, Loader2, Sun, Moon, Bell } from 'lucide-react';
import { toast } from 'sonner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  useSocket,
  type AttackAckEvent,
  type AttackCommandAckEvent,
  type AttackCommandEvent,
  type LiveNetworkEvent,
  type NetworkRemovedEvent,
  type SensorStatusEvent,
} from '@/hooks/use-socket';


type SortField = 'ssid' | 'bssid' | 'signal' | 'classification' | 'last_seen';
type SortDirection = 'asc' | 'desc';

interface ActivityItem {
  id: string;
  type: 'threat' | 'command' | 'status' | 'ack';
  title: string;
  detail: string;
  timestamp: string;
}

interface TelemetryData {
  sensorStatus: 'online' | 'offline' | 'warning';
  backendStatus: 'connected' | 'disconnected' | 'error';
  discoveredNetworks: number;
  activeAttacks: number;
  lastUpdate: string;
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
    return 'bg-red-950/40 text-red-400 border border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
  }
  if (classification === 'SUSPICIOUS') {
    return 'bg-amber-950/40 text-amber-400 border border-amber-500/50 shadow-[0_0_10px_rgba(245,158,11,0.2)]';
  }
  return 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]';
}

function TelemetryStatusBadge({ status, icon, label }: { status: string; icon: React.ReactNode; label: string }) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
      case 'connected':
        return 'text-emerald-400 bg-emerald-950/50 border-emerald-700/50';
      case 'offline':
      case 'disconnected':
        return 'text-red-400 bg-red-950/50 border-red-700/50';
      case 'warning':
      case 'error':
        return 'text-amber-400 bg-amber-950/50 border-amber-700/50';
      default:
        return 'text-slate-400 bg-slate-950/50 border-slate-700/50';
    }
  };

  return (
    <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md border text-xs font-medium ${getStatusColor(status)}`}>
      {icon}
      <span>{label}</span>
    </div>
  );
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
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);
  const [networks, setNetworks] = useState<LiveNetworkEvent[]>([]);
  const [sensorStatuses, setSensorStatuses] = useState<SensorStatusEvent[]>([]);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [hasNetworkSnapshot, setHasNetworkSnapshot] = useState(false);
  const [hasSensorSnapshot, setHasSensorSnapshot] = useState(false);
  const [huntTarget, setHuntTarget] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [focusedSuggestionIndex, setFocusedSuggestionIndex] = useState(-1);
  const [attackState, setAttackState] = useState<string | null>(null);

  useEffect(() => {
    setIsSearching(true);
    const timer = setTimeout(() => {
      setDebouncedSearchQuery(searchQuery);
      setIsSearching(false);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);
  const [sortField, setSortField] = useState<SortField>('last_seen');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [telemetry, setTelemetry] = useState<TelemetryData>({
    sensorStatus: 'offline',
    backendStatus: 'disconnected',
    discoveredNetworks: 0,
    activeAttacks: 0,
    lastUpdate: new Date().toISOString()
  });

  const signalHistoryRef = useRef<Record<string, number[]>>({});

  const apiBase = (
    process.env.NEXT_PUBLIC_API_URL ||
    process.env.NEXT_PUBLIC_BACKEND_URL ||
    'http://localhost:5000'
  ).replace(/\/$/, '');

  const appendActivity = (item: ActivityItem) => {
    setActivity((current) => [item, ...current].slice(0, 20));
  };

  const updateTelemetry = () => {
    const onlineSensors = sensorStatuses.filter(s => s.status === 'online').length;
    const totalSensors = sensorStatuses.length;
    
    let sensorStatus: 'online' | 'offline' | 'warning' = 'offline';
    if (onlineSensors === totalSensors && totalSensors > 0) {
      sensorStatus = 'online';
    } else if (onlineSensors > 0) {
      sensorStatus = 'warning';
    }

    const activeAttacks = networks.filter(n => 
      n.classification === 'ROGUE'
    ).length;

    setTelemetry({
      sensorStatus,
      backendStatus: 'connected', // Will be updated based on actual connection status
      discoveredNetworks: networks.length,
      activeAttacks,
      lastUpdate: new Date().toISOString()
    });
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

  // Update telemetry when networks, sensors, or connection status changes
  useEffect(() => {
    updateTelemetry();
  }, [networks, sensorStatuses, isConnected]);

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

  const suggestions = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const query = searchQuery.toLowerCase().trim();
    return networks
      .filter(n => 
        (n.ssid || 'Hidden').toLowerCase().includes(query) || 
        n.bssid.replace(/[:-]/g, '').toUpperCase().includes(query.replace(/[:-]/g, '').toUpperCase())
      )
      .slice(0, 5); // Limit to 5 suggestions
  }, [searchQuery, networks]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setFocusedSuggestionIndex(prev => 
        prev < suggestions.length - 1 ? prev + 1 : prev
      );
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setFocusedSuggestionIndex(prev => prev > 0 ? prev - 1 : -1);
    } else if (e.key === 'Enter') {
      if (focusedSuggestionIndex >= 0 && suggestions[focusedSuggestionIndex]) {
        setSearchQuery(suggestions[focusedSuggestionIndex].ssid || suggestions[focusedSuggestionIndex].bssid);
        setShowSuggestions(false);
      }
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
    }
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const networkList = useMemo(() => {
    let filtered = [...networks];

    if (debouncedSearchQuery) {
      const query = debouncedSearchQuery.toLowerCase().trim();
      
      filtered = filtered.filter((network) => {
        const ssidMatch = (network.ssid || 'Hidden').toLowerCase().includes(query);
        
        // Normalize MAC for comparison (handles colons, hyphens, and partials)
        const normalizedQuery = query.replace(/[:-]/g, '').toUpperCase();
        const normalizedBssid = network.bssid.replace(/[:-]/g, '').toUpperCase();
        const bssidMatch = normalizedBssid.includes(normalizedQuery);

        return ssidMatch || bssidMatch;
      });
    }

    return filtered.sort((left, right) => {
      let comparison = 0;
      
      switch (sortField) {
        case 'ssid':
          comparison = (left.ssid || 'Hidden').localeCompare(right.ssid || 'Hidden');
          break;
        case 'bssid':
          comparison = left.bssid.localeCompare(right.bssid);
          break;
        case 'signal':
          const leftSignal = left.signal ?? -999;
          const rightSignal = right.signal ?? -999;
          comparison = leftSignal - rightSignal;
          break;
        case 'classification':
          comparison = left.classification.localeCompare(right.classification);
          break;
        case 'last_seen':
          const leftTime = new Date(left.last_seen).getTime();
          const rightTime = new Date(right.last_seen).getTime();
          comparison = leftTime - rightTime;
          break;
      }
      
      return sortDirection === 'asc' ? comparison : -comparison;
    });
  }, [networks, sortField, sortDirection]);

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
<div className="space-y-6 mt-2">
      
      {/* كارت حالة الهجوم - نيون خطر هادي */}
      {attackState && (
        <Card className="border-emerald-500/20 bg-emerald-950/10 shadow-[0_0_15px_rgba(16,185,129,0.05)]">
          <CardContent className="pt-6 text-sm text-emerald-400 font-medium animate-pulse">
            <span className="mr-2">⚡</span> {attackState}
          </CardContent>
        </Card>
      )}

      {/* الكارد الأساسي للداشبورد */}
      <Card className="bg-slate-900 overflow-hidden border-none shadow-none py-0">
          <CardHeader className="p-0 border-none bg-transparent">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 w-full">
              
              {/* القسم الشمال: العنوان والبحث النيون */}
              <div className="flex flex-col sm:flex-row sm:items-center gap-4 flex-1 w-full">
                <CardTitle className="text-emerald-400 drop-shadow-[0_0_10px_rgba(52,211,153,0.7)] text-xl font-bold tracking-tight whitespace-nowrap">
                  ZeinaGuard
                </CardTitle>

                <div className="relative w-full flex-1">
                  <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                    {isSearching ? (
                      <Loader2 className="h-4 w-4 text-emerald-500 animate-spin" />
                    ) : (
                      <Search className="h-4 w-4 text-emerald-500/70" />
                    )}
                  </div>
                  <Input
                    type="text"
                    placeholder="Search SSID or MAC address"
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      setShowSuggestions(true);
                      setFocusedSuggestionIndex(-1);
                    }}
                    onFocus={() => setShowSuggestions(true)}
                    onKeyDown={handleKeyDown}
                    onBlur={() => {
                      setTimeout(() => setShowSuggestions(false), 200);
                    }}
                    className="h-10 pl-10 pr-10 w-full bg-emerald-950/20 border-emerald-500/30 text-emerald-50 placeholder:text-emerald-500/40 focus-visible:ring-emerald-500/40 focus-visible:border-emerald-500/60 shadow-[0_0_10px_rgba(16,185,129,0.1)] focus:shadow-[0_0_20px_rgba(16,185,129,0.2)] transition-all duration-300 outline-none"
                    aria-label="Search networks"
                  />
                  
                  {/* الاقتراحات - نيون غامق */}
                  {showSuggestions && suggestions.length > 0 && (
                    <div 
                      id="search-suggestions"
                      className="absolute z-50 w-full mt-2 bg-slate-900 border border-emerald-500/20 rounded-lg shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150"
                      role="listbox"
                    >
                      {suggestions.map((suggestion, index) => (
                        <button
                          key={suggestion.bssid}
                          className={`w-full px-4 py-3 text-left text-sm flex flex-col gap-1 transition-colors border-b border-emerald-500/10 last:border-0 ${
                            index === focusedSuggestionIndex ? 'bg-emerald-500/20 text-white' : 'text-emerald-300/70 hover:bg-emerald-950/40'
                          }`}
                          onClick={() => {
                            setSearchQuery(suggestion.ssid || suggestion.bssid);
                            setShowSuggestions(false);
                          }}
                        >
                          <span className="font-bold text-emerald-50">{suggestion.ssid || 'Hidden'}</span>
                          <span className="text-xs text-emerald-500/50 font-mono">{suggestion.bssid}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              
              {/* القسم اليمين: التليميتري النيون الموحد */}
              <div className="flex flex-wrap items-center gap-2 lg:ml-auto">
                <TelemetryStatusBadge 
                  status={telemetry.sensorStatus}
                  icon={<Shield className="w-3.5 h-3.5 drop-shadow-[0_0_3px_rgba(52,211,153,0.5)]" />}
                  label={`Sensor ${telemetry.sensorStatus}`}
                />
                <TelemetryStatusBadge 
                  status={telemetry.backendStatus}
                  icon={<Server className="w-3.5 h-3.5 drop-shadow-[0_0_3px_rgba(52,211,153,0.5)]" />}
                  label={`Backend ${telemetry.backendStatus}`}
                />
                <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md border border-emerald-500/20 bg-emerald-950/20 text-emerald-400/90 text-xs font-medium shadow-[0_0_8px_rgba(16,185,129,0.05)]">
                  <Wifi className="w-3.5 h-3.5 text-emerald-500 drop-shadow-[0_0_3px_rgba(16,185,129,0.5)]" />
                  <span>{telemetry.discoveredNetworks} Networks</span>
                </div>
                <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md border border-emerald-500/20 bg-emerald-950/20 text-emerald-400/90 text-xs font-medium shadow-[0_0_8px_rgba(16,185,129,0.05)]">
                  <Clock className="w-3.5 h-3.5 text-emerald-500 drop-shadow-[0_0_3px_rgba(16,185,129,0.5)]" />
                  <span>
                    {mounted ? new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '--:--'} Cairo
                  </span>
                </div>
              </div>
            </div>
          </CardHeader>

          <CardContent className="px-0">
            {loading ? (
              <div className="flex h-64 items-center justify-center text-emerald-500/50">
                <Activity className="mr-2 h-5 w-5 animate-spin" />
                Initializing Neon Grid...
              </div>
            ) : (
              /* الجدول النيون المطور */
              <div className="overflow-x-auto border border-emerald-500/10 bg-slate-900/80 backdrop-blur-md rounded-lg shadow-[0_0_30px_rgba(0,0,0,0.4)]">
                <div className="w-full">
                  
                  {/* موبايل فيو - نيون ستايل */}
                  <div className="block lg:hidden">
                    {networkList.map((network) => (
                      <div key={network.bssid} className="border-b border-emerald-500/10 p-4 last:border-b-0">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <div className="font-semibold text-emerald-50 text-sm drop-shadow-[0_0_5px_rgba(16,185,129,0.3)]">
                              {network.ssid || 'Hidden'}
                            </div>
                            <span className={`rounded-full px-2 py-1 text-xs font-semibold ${classificationClasses(network.classification)}`}>
                              {network.classification}
                            </span>
                          </div>
                          <Button
                            type="button"
                            size="sm"
                            className="bg-transparent border border-red-500/40 text-red-500 hover:bg-red-500/20 hover:shadow-[0_0_15px_rgba(239,68,68,0.4)] transition-all duration-300 font-bold"
                            onClick={() => handleAttack(network)}
                          >
                            Attack
                          </Button>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          <div className="bg-emerald-950/30 border border-emerald-500/10 rounded px-2 py-1">
                            <span className="text-emerald-500/50">BSSID:</span>
                            <span className="ml-1 font-mono text-emerald-400">{network.bssid}</span>
                          </div>
                          <div className="bg-emerald-950/30 border border-emerald-500/10 rounded px-2 py-1">
                            <span className="text-emerald-500/50">Signal:</span>
                            <span className="ml-1 text-emerald-100">{network.signal ?? 'N/A'} dBm</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* ديسكتوب فيو - نيون ستايل */}
                  <table className="hidden lg:table w-full">
                    <thead>
                      <tr className="border-b border-emerald-500/20 bg-emerald-950/10 backdrop-blur-sm">
                        <th className="px-3 py-3 text-left">
                          <button onClick={() => handleSort('ssid')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300 transition-colors">
                            SSID <ArrowUpDown className="h-3 w-3" />
                          </button>
                        </th>
                        <th className="px-3 py-3 text-left">
                          <button onClick={() => handleSort('bssid')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300 transition-colors">
                            BSSID <ArrowUpDown className="h-3 w-3" />
                          </button>
                        </th>
                        <th className="px-3 py-3 text-left">
                          <button onClick={() => handleSort('signal')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300 transition-colors">
                            Signal <ArrowUpDown className="h-3 w-3" />
                          </button>
                        </th>
                        <th className="px-3 py-3 text-left">
                          <button onClick={() => handleSort('classification')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300 transition-colors">
                            Class <ArrowUpDown className="h-3 w-3" />
                          </button>
                        </th>
                        <th className="px-3 py-3 text-left">
                          <button onClick={() => handleSort('last_seen')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300 transition-colors">
                            Last Seen <ArrowUpDown className="h-3 w-3" />
                          </button>
                        </th>
                        <th className="px-3 py-3 text-left text-emerald-400 font-semibold">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {networkList.map((network, index) => (
                        <tr 
                          key={network.bssid} 
                          className={`border-b border-emerald-500/5 hover:bg-emerald-500/5 transition-all duration-200 ${
                            index % 2 === 0 ? 'bg-slate-900/40' : 'bg-slate-800/20'
                          }`}
                        >
                          <td className="px-3 py-4">
                            <div className="font-semibold text-emerald-50 text-base truncate drop-shadow-[0_0_5px_rgba(16,185,129,0.2)]">
                              {network.ssid || 'Hidden'}
                            </div>
                          </td>
                          <td className="px-3 py-4">
                            <div className="font-mono text-sm text-emerald-400/80 bg-emerald-950/30 border border-emerald-500/20 rounded px-2 py-1 inline-block truncate">
                              {network.bssid}
                            </div>
                          </td>
                          <td className="px-3 py-4">
                            <div className={`text-base font-medium ${
                              network.signal && network.signal > -60 ? 'text-emerald-400' :
                              network.signal && network.signal > -75 ? 'text-amber-400' :
                              network.signal ? 'text-red-400' : 'text-emerald-500/50'
                            }`}>
                              {network.signal ?? 'N/A'} dBm
                            </div>
                          </td>
                          <td className="px-3 py-4">
                            <span className={`rounded-full px-3 py-1 text-sm font-semibold shadow-sm ${classificationClasses(network.classification)}`}>
                              {network.classification}
                            </span>
                          </td>
                          <td className="px-3 py-4">
                            <div className="text-base text-emerald-100/60">
                              {relativeLastSeen(network.last_seen)}
                            </div>
                          </td>
                          <td className="px-3 py-4">
                            <Button
                              type="button"
                              size="sm"
                              className="bg-transparent border border-red-500/40 text-red-500 hover:bg-red-500/20 hover:shadow-[0_0_15px_rgba(239,68,68,0.4)] transition-all duration-300 shadow-sm font-bold transform hover:scale-105 whitespace-nowrap"
                              onClick={() => handleAttack(network)}
                            >
                              Attack
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
    </div>
  );
}