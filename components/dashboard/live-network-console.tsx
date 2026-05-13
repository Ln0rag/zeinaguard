'use client';

import { useEffect, useMemo, useState, useCallback, useRef } from 'react';
import { useTheme } from 'next-themes';
import { Activity, ArrowUpDown, Clock, Search, Server, Shield, Wifi, Users, Lock, Unlock, Loader2, CheckCircle2, Bell, BellOff } from 'lucide-react';
import { toast } from 'sonner';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  useSocket,
  type AttackAckEvent,
  type AttackCommandAckEvent,
  type AttackCommandEvent,
  type SensorStatusEvent,
} from '@/hooks/use-socket';

export interface LiveNetworkEvent {
  was_hidden?: boolean;
  ssid?: string;
  bssid: string;
  classification?: 'ROGUE' | 'SUSPICIOUS' | 'LEGIT' | string;
  sensor_id?: number;
  channel?: number | null;
  frequency?: number | null;
  signal?: number | null;
  last_seen?: string;
  distance?: string | null;
  auth?: string | null;
  wps?: string | null;
  encryption?: string | null;
  uptime?: string | null;
  clients?: any[];
  clients_count?: number | null;
  manufacturer?: string | null;
}


type SortField = 'ssid' | 'bssid' | 'signal' | 'classification' | 'uptime' | 'channel' | 'clients';
type SortDirection = 'asc' | 'desc';

interface TelemetryData { sensorStatus: 'online' | 'offline' | 'warning'; backendStatus: 'connected' | 'disconnected' | 'error'; discoveredNetworks: number; activeAttacks: number; lastUpdate: string; }

interface NotificationEvent {
  id: string;
  type: 'rogue' | 'attack_start' | 'attack_end' | 'attack_aborted' | 'purge';
  title: string;
  time: string;
  bssid: string;
  ssid?: string;
  channel?: number | null;
  signal?: number | null;
  manufacturer?: string | null;
  // الحقول الجديدة اللي حلت المشكلة
  sensor_id?: string;
  hostname?: string;
  interface?: string;
  uptime?: number;
  // حقول الـ Purge
  purge_count?: number;
  purge_type?: string;
  report_name?: string;
  download_url?: string;
}

function estimateDistance(signal: number | null | undefined): string {
  if (!signal || signal === 0 || signal === -999) return '--';
  if (signal >= -40) return '~ 1m';
  if (signal >= -55) return '~ 3m';
  if (signal >= -65) return '~ 7m';
  if (signal >= -75) return '~ 15m';
  if (signal >= -85) return '~ 25m';
  return '30m+';
}

function parseUptimeSeconds(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 0;
}

function elapsedSecondsSince(value?: string | null): number {
  if (!value) return 0;
  const lastSeenMs = new Date(value).getTime();
  if (Number.isNaN(lastSeenMs)) return 0;
  return Math.max(0, Math.floor((Date.now() - lastSeenMs) / 1000));
}

function RouterUptimeValue({ baseSeconds, lastSeen }: { baseSeconds: number; lastSeen?: string | null }) {
  const resolveSeconds = useCallback(
    () => baseSeconds + elapsedSecondsSince(lastSeen),
    [baseSeconds, lastSeen],
  );
  const [displaySeconds, setDisplaySeconds] = useState(resolveSeconds);

  useEffect(() => {
    setDisplaySeconds((current) => {
      const next = resolveSeconds();
      if (next < current - 5) return next;
      return Math.max(current, next);
    });
  }, [resolveSeconds]);

  useEffect(() => {
    const interval = setInterval(() => {
      setDisplaySeconds((current) => current + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  if (!Number.isFinite(displaySeconds) || displaySeconds <= 0) {
    return <span className="inline-block min-w-[112px] font-mono tabular-nums whitespace-nowrap">--</span>;
  }

  const normalized = Math.max(0, Math.floor(displaySeconds));
  const d = Math.floor(normalized / 86400);
  const h = Math.floor((normalized % 86400) / 3600);
  const m = Math.floor((normalized % 3600) / 60);
  const s = Math.floor(normalized % 60);
  const parts = [
    d > 0 ? `${d}d` : null,
    h > 0 ? `${h}h` : null,
    m > 0 ? `${m}m` : null,
    `${s.toString().padStart(2, '0')}s`,
  ].filter(Boolean);

  return (
    <span className="inline-flex min-w-[11ch] justify-start gap-[0.55ch] whitespace-nowrap font-mono tabular-nums leading-none">
      {parts.map((part, index) => (
        <span key={index} className="inline-block min-w-[2.7ch] text-left">
          {part}
        </span>
      ))}
    </span>
  );
}

function classificationClasses(classification?: string) {
  const cls = (classification || '').toUpperCase();
  if (cls === 'ROGUE') return 'bg-red-950/40 text-red-400 border border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
  if (cls === 'SUSPICIOUS') return 'bg-amber-950/40 text-amber-400 border border-amber-500/50 shadow-[0_0_10px_rgba(245,158,11,0.2)]';
  return 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]';
}

function TelemetryStatusBadge({ status, icon, label }: { status: string; icon: React.ReactNode; label: string }) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': case 'connected': 
        return 'border-emerald-500/80 bg-emerald-950/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.5)] [&>svg]:drop-shadow-[0_0_5px_rgba(16,185,129,0.9)]';
      case 'offline': case 'disconnected': 
        return 'border-red-500/80 bg-red-950/40 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.5)] [&>svg]:drop-shadow-[0_0_5px_rgba(239,68,68,0.9)]';
      case 'warning': case 'error': 
        return 'border-amber-500/80 bg-amber-950/40 text-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.5)] [&>svg]:drop-shadow-[0_0_5px_rgba(245,158,11,0.9)]';
      default: 
        return 'border-slate-700/80 bg-slate-950/40 text-slate-400 shadow-[0_0_10px_rgba(100,116,139,0.3)] [&>svg]:drop-shadow-[0_0_5px_rgba(100,116,139,0.9)]';
    }
  };
  return (
    <div className={`h-8 flex items-center justify-center gap-2 px-3 rounded-md border transition-all duration-300 text-xs font-bold ${getStatusColor(status)}`}>
      {icon}<span>{label}</span>
    </div>
  );
}

function normalizeNetwork(network: any): LiveNetworkEvent {
  const clients = Array.isArray(network.clients) ? network.clients : [];
  const rawClientsCount = network.clients_count ?? network.clients;
  const parsedClientsCount = Array.isArray(rawClientsCount)
    ? rawClientsCount.length
    : Number(rawClientsCount);

  return {
    ...network,
    bssid: String(network.bssid || '').trim().toUpperCase().replace(/-/g, ':'),
    was_hidden: Boolean(network.was_hidden),
    classification: network.classification || 'LEGIT',
    sensor_id: network.sensor_id || 0,
    channel: network.channel || 0,
    signal: network.signal || 0,
    last_seen: network.last_seen || network.timestamp || new Date().toISOString(),
    distance: network.distance && network.distance !== 'Unknown' ? String(network.distance) : null,
    auth: (network.auth || network.auth_type) && !['unknown', 'none', 'n/a'].includes(String(network.auth || network.auth_type).toLowerCase()) ? String(network.auth || network.auth_type) : null,
    wps: (network.wps || network.wps_info) && !['unknown', 'none', 'n/a'].includes(String(network.wps || network.wps_info).toLowerCase()) ? String(network.wps || network.wps_info) : null,
    encryption: network.encryption && !['unknown', 'none', 'n/a'].includes(String(network.encryption).toLowerCase()) ? String(network.encryption) : null,
    uptime: (network.uptime || network.uptime_seconds) && String(network.uptime || network.uptime_seconds).toLowerCase() !== 'unknown' ? String(network.uptime || network.uptime_seconds) : null,
    clients,
    clients_count: Number.isFinite(parsedClientsCount) ? Math.max(0, parsedClientsCount) : clients.length,
    manufacturer: network.manufacturer && !['unknown mfr', 'unknown', 'none', 'n/a'].includes(String(network.manufacturer).toLowerCase()) ? String(network.manufacturer) : null,
  };
}


export function LiveNetworkConsole() {
  const [activeAttackBssids, setActiveAttackBssids] = useState<Set<string>>(new Set());
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);

  const [networksMap, setNetworksMap] = useState<Map<string, LiveNetworkEvent>>(new Map());
  const [sensorStatuses, setSensorStatuses] = useState<SensorStatusEvent[]>([]);
  const [hasNetworkSnapshot, setHasNetworkSnapshot] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [trustingBssids, setTrustingBssids] = useState<Set<string>>(new Set());

// حالة الإشعارات
  const [notifications, setNotifications] = useState<NotificationEvent[]>([]);
  const [hasNewNotifications, setHasNewNotifications] = useState(false);

  useEffect(() => {
    const loadNotifications = () => {
      const saved = localStorage.getItem('zeinaguard_alerts');
      if (saved) {
        try {
          setNotifications(JSON.parse(saved));
          // السطر ده هيقرأ العلامة اللي الـ GlobalAlerts عملها
          const hasUnread = localStorage.getItem('zeinaguard_unread_status') === 'true';
          setHasNewNotifications(hasUnread);
        } catch (e) {}
      }
    };

    const handleNewNotification = () => {
      loadNotifications(); // الدالة دي هتقرأ العلامة وتنور الجرس لوحدها
    };

    loadNotifications();
    
    window.addEventListener('zeinaguard_new_notification', handleNewNotification);
    return () => window.removeEventListener('zeinaguard_new_notification', handleNewNotification);
  }, []);

  useEffect(() => {
    setIsSearching(true);
    const timer = setTimeout(() => { setDebouncedSearchQuery(searchQuery); setIsSearching(false); }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const [sortField, setSortField] = useState<SortField>('ssid');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  
  const [telemetry, setTelemetry] = useState<TelemetryData>({
    sensorStatus: 'offline', backendStatus: 'disconnected', discoveredNetworks: 0, activeAttacks: 0, lastUpdate: new Date().toISOString()
  });

  const isOfflineRef = useRef(false);
  useEffect(() => {
    isOfflineRef.current = telemetry.sensorStatus === 'offline';
  }, [telemetry.sensorStatus]);

  const apiBase = (process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5000').replace(/\/$/, '');

  const updateTelemetry = useCallback((currentMap: Map<string, LiveNetworkEvent>) => {
    const onlineSensors = sensorStatuses.filter(s => s.status === 'online').length;
    const totalSensors = sensorStatuses.length;
    let sensorStatus: 'online' | 'offline' | 'warning' = 'offline';
    if (onlineSensors === totalSensors && totalSensors > 0) sensorStatus = 'online';
    else if (onlineSensors > 0) sensorStatus = 'warning';

    const activeAttacks = Array.from(currentMap.values()).filter(n => n.classification === 'ROGUE').length;
    setTelemetry((previous) => {
      if (
        previous.sensorStatus === sensorStatus &&
        previous.backendStatus === 'connected' &&
        previous.discoveredNetworks === currentMap.size &&
        previous.activeAttacks === activeAttacks
      ) {
        return previous;
      }

      return { sensorStatus, backendStatus: 'connected', discoveredNetworks: currentMap.size, activeAttacks, lastUpdate: new Date().toISOString() };
    });
  }, [sensorStatuses]);


  const handleDropdownOpen = (open: boolean) => {
    if (open) {
      setHasNewNotifications(false);
      // أول ما تفتح القائمة، بنلغي علامة الإشعارات الجديدة
      localStorage.setItem('zeinaguard_unread_status', 'false');
    }
  };

  const mergeIncomingNetworks = useCallback((incoming: any[]) => {
    if (isOfflineRef.current) return;

    setNetworksMap(prevMap => {
      const newMap = new Map(prevMap);
      let changed = false;

      incoming.forEach(rawNet => {
        const norm = normalizeNetwork(rawNet);
        const existing = newMap.get(norm.bssid);
        
        if (existing) {

          const existingUptime = parseUptimeSeconds(existing.uptime);
          const incomingUptime = parseUptimeSeconds(norm.uptime);
          const shouldRefreshUptime =
            incomingUptime > 0 &&
            (!existingUptime || incomingUptime < existingUptime - 5);
          const nextNetwork: LiveNetworkEvent = {
            ...existing,
            ...norm,
            was_hidden: norm.was_hidden || existing.was_hidden,
            classification: norm.classification, 
            manufacturer: norm.manufacturer || existing.manufacturer,
            channel: (norm.channel && norm.channel !== 0) ? norm.channel : existing.channel,
            wps: norm.wps || existing.wps,
            auth: norm.auth || existing.auth,
            encryption: norm.encryption || existing.encryption,
            uptime: shouldRefreshUptime ? norm.uptime : existing.uptime,
            last_seen: shouldRefreshUptime ? norm.last_seen : existing.last_seen,
            clients: Array.isArray(norm.clients) ? norm.clients : existing.clients,
            clients_count: norm.clients_count !== undefined ? norm.clients_count : existing.clients_count,
            signal: (norm.signal && norm.signal !== 0) ? norm.signal : existing.signal,
          };
          
          const isSame =
            existing.ssid === nextNetwork.ssid &&
            existing.classification === nextNetwork.classification &&
            existing.channel === nextNetwork.channel &&
            existing.wps === nextNetwork.wps &&
            existing.auth === nextNetwork.auth &&
            existing.encryption === nextNetwork.encryption &&
            existing.uptime === nextNetwork.uptime &&
            existing.last_seen === nextNetwork.last_seen &&
            existing.clients_count === nextNetwork.clients_count &&
            existing.signal === nextNetwork.signal &&
            existing.manufacturer === nextNetwork.manufacturer &&
            existing.was_hidden === nextNetwork.was_hidden;

          if (!isSame) {
            newMap.set(norm.bssid, nextNetwork);
            changed = true;
          }
        } else {
          newMap.set(norm.bssid, norm);
          changed = true;
        }
      });

      return changed ? newMap : prevMap;
    });
    setHasNetworkSnapshot(true);
  }, []);

  const upsertSensorStatus = useCallback((incoming: any) => {
    const msg = (incoming.message || "").toLowerCase();
    const isHardwareOffline = 
      msg.includes("disconnected") || msg.includes("physically removed") || msg.includes("error") || 
      msg.includes("lost") || msg.includes("down") || msg.includes("no such device") || 
      msg.includes("errno 19") || (incoming.status || incoming.sensor_status || "").toLowerCase() === "error";
      
    const resolvedStatus = isHardwareOffline 
      ? "offline" 
      : (["monitoring", "online", "starting"].includes((incoming.status || incoming.sensor_status || "offline").toLowerCase()) ? "online" : "offline");

    const normalizedIncoming: SensorStatusEvent = {
      ...incoming,
      status: resolvedStatus,
      connected: resolvedStatus === "online",
      last_seen: incoming.last_seen || incoming.last_heartbeat || new Date().toISOString(),
      last_heartbeat: incoming.last_heartbeat || incoming.last_seen || new Date().toISOString(),
    };

    setSensorStatuses((prev) => {
      const index = prev.findIndex((sensor) => sensor.sensor_id === normalizedIncoming.sensor_id);
      if (index === -1) {
        return [...prev, normalizedIncoming];
      }

      const next = [...prev];
      next[index] = {
        ...next[index],
        ...normalizedIncoming,
      };
      return next;
    });
  }, []);

  const { sendAttackCommand } = useSocket({
    onNetworkSnapshot: (event) => { mergeIncomingNetworks(event.data || []); },
    onSensorSnapshot: (event) => {
      setSensorStatuses(
        (event.data || []).map((s: any) => {
          const msg = (s.message || "").toLowerCase();
          const isHardwareOffline = 
            msg.includes("disconnected") || msg.includes("physically removed") || msg.includes("error") || 
            msg.includes("lost") || msg.includes("down") || msg.includes("no such device") || 
            msg.includes("errno 19") || (s.sensor_status || "").toLowerCase() === "error";
            
          const resolvedStatus = isHardwareOffline 
            ? "offline" 
            : (["monitoring", "online", "starting"].includes((s.status || s.sensor_status || "offline").toLowerCase()) ? "online" : "offline");

          return {
            ...s,
            status: resolvedStatus,
            connected: resolvedStatus === "online",
            last_seen: s.last_seen || s.last_heartbeat || new Date().toISOString(),
            last_heartbeat: s.last_heartbeat || s.last_seen || new Date().toISOString(),
          };
        }),
      );
    },
    onSensorStatusUpdate: (event) => {
      if (!event?.data?.sensor_id) return;
      upsertSensorStatus(event.data);
    },
    onNetworkRemoved: (event) => {
      const bssid = String(event.bssid || '').toUpperCase();
      setNetworksMap(prev => { const m = new Map(prev); m.delete(bssid); return m; });
    },
    onAttackCommandAck: (event) => {
      if (event.status === 'ok') {
        setActiveAttackBssids(prev => new Set(prev).add(event.bssid));
      }
    },
    onAttackAck: (event) => {
      setActiveAttackBssids(prev => {
        const next = new Set(prev);
        next.delete(event.bssid);
        return next;
      });
    },
  });

  useEffect(() => {
    updateTelemetry(networksMap);
  }, [sensorStatuses, networksMap, updateTelemetry]);

  // 1. هنضيف المرجع ده عشان نعرف هل السنسور اشتغل فعلاً قبل كده ولا لأ
  const hasBeenOnlineRef = useRef(false);

  useEffect(() => {
    // 2. لو السنسور لقط وبقى أونلاين، نسجل إنه اشتغل
    if (telemetry.sensorStatus === 'online' || telemetry.sensorStatus === 'warning') {
      hasBeenOnlineRef.current = true;
    }

    let timeoutId: NodeJS.Timeout;
    
    // 3. هنفضي الكاش *فقط* لو كان أونلاين وبعدين فصل (عشان نتجاهل حالة الـ offline المبدئية عند فتح التاب)
    if (telemetry.sensorStatus === 'offline' && hasBeenOnlineRef.current) {
      timeoutId = setTimeout(() => {
        setNetworksMap(new Map());
        hasBeenOnlineRef.current = false; // نرجعها للصفر عشان دورة التابات الجديدة
      }, 1000);
    }
    
    return () => clearTimeout(timeoutId);
  }, [telemetry.sensorStatus]);

  const loading = !hasNetworkSnapshot;

  useEffect(() => {
    let cancelled = false;
    const fetchActive = async () => {
      try {
        const res = await fetch(`${apiBase}/networks/active`, { cache: 'no-store' });
        if (!res.ok) return;
        const payload = await res.json();
        if (!cancelled && Array.isArray(payload.networks)) mergeIncomingNetworks(payload.networks);
      } catch (e) {}
    };
    fetchActive();
    return () => { cancelled = true; };
  }, [apiBase, mergeIncomingNetworks]);

  const handleSort = (field: SortField) => {
    if (sortField === field) setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDirection('asc'); }
  };

  const networkList = useMemo(() => {
    let list = Array.from(networksMap.values());

    if (debouncedSearchQuery) {
      const query = debouncedSearchQuery.toLowerCase().trim();
      list = list.filter((n) => (n.ssid || '').toLowerCase().includes(query) || n.bssid.replace(/[:-]/g, '').toLowerCase().includes(query.replace(/[:-]/g, '')));
    }

    return list.sort((left, right) => {
      let comparison = 0;
      switch (sortField) {
        case 'ssid': comparison = (left.ssid || 'Hidden').localeCompare(right.ssid || 'Hidden'); break;
        case 'bssid': comparison = left.bssid.localeCompare(right.bssid); break;
        case 'signal': comparison = (right.signal ?? -999) - (left.signal ?? -999); break;
        case 'classification': {
          // تعريف الأولوية: الـ ROGUE هو رقم 3 (الأعلى)، ثم SUSPICIOUS، ثم LEGIT
          const priority: Record<string, number> = { 'ROGUE': 3, 'SUSPICIOUS': 2, 'LEGIT': 1 };
          
          const weightLeft = priority[left.classification?.toUpperCase() || 'LEGIT'] || 0;
          const weightRight = priority[right.classification?.toUpperCase() || 'LEGIT'] || 0;
          
          // الطرح ده بيضمن إن الرقم الكبير (ROGUE) يظهر في الأول
          comparison = weightRight - weightLeft; 
          break;
        }
        case 'uptime': comparison = parseUptimeSeconds(left.uptime) - parseUptimeSeconds(right.uptime); break;
        case 'channel': comparison = (left.channel ?? 0) - (right.channel ?? 0); break;
        case 'clients': comparison = (left.clients_count ?? 0) - (right.clients_count ?? 0); break;
      }
      if (comparison === 0) return left.bssid.localeCompare(right.bssid);
      return sortDirection === 'asc' ? comparison : -comparison;
    });
  }, [networksMap, sortField, sortDirection, debouncedSearchQuery]);

  const handleAttack = (network: LiveNetworkEvent) => {
    try { 
      toast.success('ATTACK DISPATCHED', { description: `Targeting ${network.ssid}` });
      sendAttackCommand({ sensor_id: network.sensor_id || 0, bssid: network.bssid, channel: network.channel || 0 }); 
    } catch (error) { 
      console.error('Attack failed', error); 
    }
  };

  const handleTrust = async (network: LiveNetworkEvent) => {
     const bssid = network.bssid;
     setTrustingBssids(prev => new Set(prev).add(bssid));
     try {
       const response = await fetch(`${apiBase}/trust`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ bssid, ssid: network.ssid || 'Hidden' }),
       });
       if (!response.ok) throw new Error('Failed to trust network');
       toast.success('Network Trusted', { description: `${bssid} added to trusted whitelist.` });
     } catch (error) {
       toast.error('Whitelist Failed', { description: error instanceof Error ? error.message : 'Network issue' });
     } finally {
       setTrustingBssids(prev => {
         const next = new Set(prev);
         next.delete(bssid);
         return next;
       });
     }
  };

  const getNotificationColor = (type: NotificationEvent['type'] | 'attack_aborted') => {
    switch (type) {
      case 'rogue': return 'border-red-500 text-red-400';
      case 'attack_start': return 'border-emerald-500 text-emerald-400';
      case 'attack_end': return 'border-blue-500 text-blue-400';
      case 'attack_aborted': return 'border-orange-500 text-orange-400';
      case 'purge': return 'border-purple-500 text-purple-400';
      default: return 'border-slate-500 text-slate-400';
    }
  };

  const purgeTypeLabel = (type?: string) => {
    switch (type) {
      case 'today': return 'Today\'s Records';
      case 'weekly': return 'Last 7 Days';
      case 'monthly': return 'Last 30 Days';
      case 'range': return 'Custom Range';
      case 'all': return 'All Records';
      default: return type || 'Unknown';
    }
  };

  return (
    <div className="space-y-6">
      <Card className="bg-slate-900 overflow-hidden border-none shadow-none py-0">
          <CardHeader className="p-0 border-none bg-transparent">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 w-full border-b border-emerald-500/10 pb-4">
              
              <div className="flex flex-col sm:flex-row sm:items-center gap-4 flex-1 w-full">
                <CardTitle className="text-emerald-400 drop-shadow-[0_0_10px_rgba(52,211,153,0.7)] text-xl font-bold tracking-tight whitespace-nowrap">ZeinaGuard</CardTitle>
                
                <div className="relative w-full flex-1">
                  <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                    {isSearching ? (
                      <Loader2 className="h-4 w-4 text-emerald-400 animate-spin drop-shadow-[0_0_5px_rgba(16,185,129,0.9)]" />
                    ) : (
                      <Search className="h-4 w-4 text-emerald-400 drop-shadow-[0_0_5px_rgba(16,185,129,0.9)]" />
                    )}
                  </div>
                  <Input 
                    type="text" 
                    placeholder="Search SSID or MAC address" 
                    value={searchQuery} 
                    onChange={(e) => setSearchQuery(e.target.value)} 
                    className="h-8 pl-10 pr-4 w-full rounded-md border border-emerald-500/80 bg-emerald-950/40 text-emerald-400 font-bold placeholder:text-emerald-500/60 placeholder:font-medium focus-visible:ring-1 focus-visible:ring-emerald-500/80 focus-visible:border-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)] transition-all duration-300 outline-none" 
                  />
                </div>
              </div>
              
              <div className="flex flex-wrap items-center gap-2 lg:ml-auto">
                <TelemetryStatusBadge status={telemetry.sensorStatus} icon={<Shield className="w-4 h-4" />} label={`Sensor ${telemetry.sensorStatus}`} />
                <TelemetryStatusBadge status={telemetry.backendStatus} icon={<Server className="w-4 h-4" />} label={`Backend ${telemetry.backendStatus}`} />
                
                <div className="h-8 flex items-center justify-center gap-2 px-3 rounded-md border border-emerald-500/80 bg-emerald-950/40 text-emerald-400 text-xs font-bold shadow-[0_0_10px_rgba(16,185,129,0.5)] transition-all duration-300">
                  <Wifi className="w-4 h-4 drop-shadow-[0_0_5px_rgba(16,185,129,0.9)]" />
                  <span>{telemetry.discoveredNetworks} Networks</span>
                </div>
                
                <div className="h-8 flex items-center justify-center gap-2 px-3 rounded-md border border-emerald-500/80 bg-emerald-950/40 text-emerald-400 text-xs font-bold shadow-[0_0_10px_rgba(16,185,129,0.5)] transition-all duration-300">
                  <Clock className="w-4 h-4 drop-shadow-[0_0_5px_rgba(16,185,129,0.9)]" />
                  <span>{mounted ? new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '--:--'} Cairo</span>
                </div>
                {/* Dropdown Menu للإشعارات (أكبر، أعرض، وأكثر وضوحاً مع ميزة البحث) */}
                <DropdownMenu onOpenChange={handleDropdownOpen}>
                  <DropdownMenuTrigger asChild>
                    <Button 
                      type="button"
                      className="mr-3 h-9 w-9 p-0 rounded-md flex items-center justify-center border transition-all duration-300 border-emerald-500/80 bg-emerald-950/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.5)] hover:bg-emerald-950/40 hover:text-emerald-400 hover:border-emerald-500/80 outline-none"
                    >
                      <div className="relative">
                        <Bell className="w-5 h-5 drop-shadow-[0_0_5px_rgba(16,185,129,0.9)]" />
                        {hasNewNotifications && (
                          <span className="absolute -top-1.5 -right-1.5 flex h-3 w-3">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
                          </span>
                        )}
                      </div>
                    </Button>
                  </DropdownMenuTrigger>
                  
                  {/* زيادة العرض إلى 550px لسهولة القراءة */}
                  <DropdownMenuContent align="end" className="w-[550px] bg-slate-900 border-emerald-500/50 shadow-[0_0_40px_rgba(0,0,0,0.7)] text-emerald-50 p-0">
                    <DropdownMenuLabel className="text-emerald-400 font-bold flex justify-between items-center text-base py-4 px-5">
                      Security Events
                      <div className="flex items-center gap-6">
                        <span className="text-sm text-emerald-500/50 font-normal">Last 50 events</span>
                        {/* زرار لتنظيف السجل */}
                        <button 
                          onClick={(e) => { 
                            e.stopPropagation(); 
                            setNotifications([]); 
                            localStorage.removeItem('zeinaguard_alerts'); 
                          }} 
                          className="text-sm text-red-400/80 hover:text-red-400 font-bold transition-colors outline-none cursor-pointer"
                        >
                          Clear
                        </button>
                      </div>
                    </DropdownMenuLabel>
                    <DropdownMenuSeparator className="bg-emerald-500/20 m-0" />
                    
                    {/* زيادة طول منطقة التمرير إلى 600px */}
                    <ScrollArea className="h-[600px]">
                      {notifications.length === 0 ? (
                        <div className="p-12 text-center text-base text-slate-500 font-mono">No events recorded yet.</div>
                      ) : (
                        notifications.map((notif) => {
                          // تحديد نوع التنبيه
                          const isPurge = notif.type === 'purge';
                          const isHardware = !isPurge && Boolean(notif.sensor_id);

                          return (
                            <div 
                              key={notif.id} 
                              onClick={() => {
                                if (isPurge && notif.download_url) {
                                  // لما تضغط على إشعار الـ Purge ينزل الريبورت مباشرة
                                  window.open(notif.download_url, '_blank');
                                } else {
                                  setSearchQuery(notif.bssid);
                                }
                              }}
                              className={`p-5 border-b border-emerald-500/10 transition-all cursor-pointer hover:bg-emerald-500/10 active:scale-[0.99] border-l-4 ${getNotificationColor(notif.type)}`}
                            >
                              <div className="flex flex-col gap-2.5">
                                <div className="flex justify-between items-start">
                                  <h4 className="font-bold text-[13px] tracking-wide uppercase">{notif.title}</h4>
                                  <span className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                                    <Clock className="w-3 h-3" /> {notif.time}
                                  </span>
                                </div>
                                
                                {isPurge ? (
                                  /* --- 3. قالب تنبيهات الـ Purge (تنظيف قاعدة البيانات) --- */
                                  <>
                                    <p className="text-[12px] text-slate-300 leading-tight">
                                      Cleaned <span className="text-purple-400 font-bold">{notif.purge_count}</span> threat records from <span className="text-purple-400 font-bold">{purgeTypeLabel(notif.purge_type)}</span>
                                    </p>
                                    <div className="pt-1">
                                      <div className="text-[10px] font-mono text-slate-400 flex flex-wrap items-center gap-x-2 gap-y-2 leading-none">
                                        <span className="bg-purple-500/10 text-purple-400/90 px-2 py-1 rounded border border-purple-500/20">
                                          RECORDS: <span className="font-bold">{notif.purge_count}</span>
                                        </span>
                                        <span className="bg-slate-800/50 px-1.5 py-1 rounded border border-slate-700/50">
                                          SCOPE: <span className="text-purple-300">{purgeTypeLabel(notif.purge_type)}</span>
                                        </span>
                                        {notif.report_name && (
                                          <span className="bg-purple-500/10 text-purple-300 px-2 py-1 rounded border border-purple-500/20 flex items-center gap-1">
                                            📄 <span className="underline">Download Report</span>
                                          </span>
                                        )}
                                      </div>
                                    </div>
                                  </>
                                ) : (
                                  <>
                                    <p className="text-[12px] text-slate-300 leading-tight">
                                      Target: <span className="text-emerald-400 font-bold">
                                        {notif.ssid && notif.ssid !== 'Unknown' ? notif.ssid : (notif.bssid || 'Target Unknown')}
                                      </span>
                                    </p>

                                    <div className="pt-1">
                                      {isHardware ? (
                                        /* --- 1. قالب تنبيهات السنسور والادابتور (Hardware) --- */
                                        <div className="text-[10px] font-mono text-slate-400 flex flex-wrap items-center gap-x-2 gap-y-2 leading-none">
                                          <span className="bg-emerald-500/10 text-emerald-400/90 px-2 py-1 rounded border border-emerald-500/20">
                                            ID: <span className="font-bold">#{notif.sensor_id}</span>
                                          </span>
                                          <span className="bg-slate-800/50 px-1.5 py-1 rounded border border-slate-700/50">
                                            NAME: <span className="text-emerald-300">{notif.hostname && notif.hostname !== 'N/A' ? notif.hostname : 'linux'}</span>
                                          </span>
                                          <span className="bg-slate-800/50 px-1.5 py-1 rounded border border-slate-700/50">
                                            IFACE: <span className="text-emerald-300">{notif.interface && notif.interface !== 'N/A' ? notif.interface : 'wlan1'}</span>
                                          </span>
                                          <span className="bg-slate-800/50 px-1.5 py-1 rounded border border-slate-700/50">
                                            UPTIME: <span className="text-emerald-300">
                                              {typeof notif.uptime === 'number' ? (
                                                notif.uptime >= 3600 
                                                  ? `${Math.floor(notif.uptime / 3600)}h ${Math.floor((notif.uptime % 3600) / 60)}m` 
                                                  : notif.uptime >= 60 
                                                    ? `${Math.floor(notif.uptime / 60)}m ${notif.uptime % 60}s` 
                                                    : `${notif.uptime}s`
                                              ) : 'Active'}
                                            </span>
                                          </span>
                                        </div>
                                      ) : (
                                        /* --- 2. قالب تنبيهات الشبكات الروج (Network) --- */
                                        <div className="text-xs font-mono text-slate-400 flex flex-wrap items-center gap-x-3 gap-y-1.5 leading-none">
                                          <span className="bg-slate-800/50 px-2 py-1 rounded border border-slate-700/50">
                                            BSSID: <span className="text-emerald-300">{notif.bssid}</span>
                                          </span>
                                          <span className="text-slate-700 font-bold">|</span>
                                          <span className="bg-slate-800/50 px-2 py-1 rounded border border-slate-700/50">
                                            Ch: <span className="text-emerald-300">{notif.channel || '--'}</span>
                                          </span>
                                          <span className="text-slate-700 font-bold">|</span>
                                          <span className="bg-slate-800/50 px-2 py-1 rounded border border-slate-700/50">
                                            Sig: <span className="text-emerald-300">{notif.signal ? `${notif.signal}dBm` : '--'}</span>
                                          </span>
                                          {notif.manufacturer && (
                                            <>
                                              <span className="text-slate-700 font-bold">|</span>
                                              <span className="text-[10px] text-slate-500 italic">Mfr: {notif.manufacturer}</span>
                                            </>
                                          )}
                                        </div>
                                      )}
                                    </div>
                                  </>
                                )}
                              </div>
                            </div>
                          );
                        })
                      )}
                    </ScrollArea>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>

            </div>
          </CardHeader>

          <CardContent className="px-0">
            {loading ? (
              <div className="flex h-64 items-center justify-center text-emerald-500/50"><Activity className="mr-2 h-5 w-5 animate-spin" />Initializing Neon Grid...</div>
            ) : (
              <div className="overflow-x-auto border border-emerald-500/10 bg-slate-900/80 backdrop-blur-md rounded-lg shadow-[0_0_30px_rgba(0,0,0,0.4)]">
                <div className="w-full">
                  <table className="hidden lg:table w-full">
                    <thead>
                      <tr className="border-b border-emerald-500/20 bg-emerald-950/10 backdrop-blur-sm">
                        <th className="px-3 py-3 text-left"><button onClick={() => handleSort('ssid')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300">WiFi <ArrowUpDown className="h-3 w-3" /></button></th>
                        <th className="px-3 py-3 text-left"><button onClick={() => handleSort('channel')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300">CH <ArrowUpDown className="h-3 w-3" /></button></th>
                        <th className="px-3 py-3 text-left"><button onClick={() => handleSort('signal')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300">Signal / Dist <ArrowUpDown className="h-3 w-3" /></button></th>
                        <th className="px-3 py-3 text-left"><span className="flex items-center gap-2 text-sm font-semibold text-emerald-400">Security</span></th>
                        <th className="px-3 py-3 text-left"><button onClick={() => handleSort('clients')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300">Clients <ArrowUpDown className="h-3 w-3" /></button></th>
                        <th className="px-3 py-3 text-left w-[120px]"><button onClick={() => handleSort('uptime')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300">UpTime <ArrowUpDown className="h-3 w-3" /></button></th>
                        <th className="px-3 py-3 text-left"><button onClick={() => handleSort('classification')} className="flex items-center gap-2 text-sm font-semibold text-emerald-400 hover:text-emerald-300">Class <ArrowUpDown className="h-3 w-3" /></button></th>
                        <th className="px-3 py-3 text-center text-emerald-400 font-semibold">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {networkList.map((network, index) => {
                        const wpsValue = network.wps || '';
                        const isWpsActive = wpsValue.toUpperCase().includes('ACTIVE') || wpsValue.toUpperCase().includes('V1');
                        const hasClients = (network.clients_count || 0) > 0;
                        const mfrValue = network.manufacturer;
                        const authValue = network.auth || network.encryption || 'Unknown';
                        const isTrusted = (network.classification || '').toUpperCase() === 'LEGIT';
                        const isTrusting = trustingBssids.has(network.bssid);
                        const distanceValue = network.distance || estimateDistance(network.signal);

                        return (
                        <tr key={network.bssid} className={`border-b border-emerald-500/5 hover:bg-emerald-500/5 transition-all duration-200 ${index % 2 === 0 ? 'bg-slate-900/40' : 'bg-slate-800/20'}`}>
                          <td className="px-3 py-4">
                            <div className="flex flex-col gap-1">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-emerald-50 text-base truncate drop-shadow-[0_0_5px_rgba(16,185,129,0.3)]">
                                  <span className="font-semibold text-emerald-50 text-base truncate">
                                    {network.ssid || 'Hidden'}
                                  </span>
                                </span>
                              </div>
                              <div className="flex items-center gap-2 mt-0.5">
                                <div className="font-mono text-[11px] text-emerald-400/70 tracking-widest bg-emerald-500/5 px-1 py-0.5 rounded border border-emerald-500/10">{network.bssid}</div>
                                {mfrValue && <span className="text-[10px] text-slate-400/90 bg-slate-800/60 px-1.5 py-0.5 rounded truncate max-w-[120px] border border-slate-700/50" title={mfrValue}>{mfrValue}</span>}
                              </div>
                            </div>
                          </td>
                          <td className="px-3 py-4">
                             <div className="font-bold text-emerald-100/90 text-sm bg-slate-800/50 px-2 py-1 rounded border border-slate-700/50 inline-block">
                                {network.channel && network.channel !== 0 ? network.channel : '--'}
                             </div>
                          </td>
                          <td className="px-3 py-4">
                            <div className="flex flex-col gap-1">
                              <div className={`text-base font-medium ${(network.signal || -999) > -60 ? 'text-emerald-400' : (network.signal || -999) > -75 ? 'text-amber-400' : network.signal && network.signal !== 0 ? 'text-red-400' : 'text-emerald-500/50'}`}>
                                {network.signal && network.signal !== 0 ? `${network.signal} dBm` : '--'}
                              </div>
                              <div className="text-xs text-slate-400 font-mono">{distanceValue || '--'}</div>
                            </div>
                          </td>
                          <td className="px-3 py-4">
                             <div className="flex flex-col gap-1.5">
                                <div className="flex items-center gap-1.5">
                                  {authValue === 'OPEN' ? <Unlock className="w-3 h-3 text-red-400" /> : <Lock className="w-3 h-3 text-emerald-400" />}
                                  <span className={`text-xs font-semibold ${authValue === 'OPEN' ? 'text-red-400' : 'text-emerald-100'}`}>{authValue}</span>
                                </div>
                                {wpsValue && wpsValue !== 'Disabled' && (
                                  <div className="text-[10px] uppercase font-bold tracking-wider">
                                    <span className="text-slate-500">WPS: </span><span className={isWpsActive ? 'text-amber-500' : 'text-emerald-500'}>ON</span>
                                  </div>
                                )}
                             </div>
                          </td>
                          <td className="px-3 py-4">
                             <div className="flex items-center gap-1.5 bg-slate-800/40 px-2 py-1 rounded-md border border-slate-700/30 w-fit">
                                <Users className={`w-4 h-4 ${hasClients ? 'text-blue-400' : 'text-slate-500'}`} />
                                <span className={`font-bold text-sm ${hasClients ? 'text-emerald-50' : 'text-slate-400'}`}>{network.clients_count || 0}</span>
                             </div>
                          </td>
                          <td className="px-3 py-4 w-[120px]">
                            <div className="text-sm text-emerald-100/70">
                              <RouterUptimeValue baseSeconds={parseUptimeSeconds(network.uptime)} lastSeen={network.last_seen} />
                            </div>
                          </td>
                          <td className="px-3 py-4">
                          <span className={`rounded-full px-3 py-1 text-sm font-semibold shadow-sm ${classificationClasses(network.classification)}`}>{network.classification || 'LEGIT'}</span>
                          </td>
                          <td className="px-3 py-4">
                            <div className="flex items-center justify-center gap-2">
                                {/* 1. زرار الـ Attack (الموجود حالياً) */}
                                <Button
                                  size="sm"
                                  variant="destructive"
                                  disabled={activeAttackBssids.has(network.bssid)} 
                                  onClick={() => handleAttack(network)}
                                  className="relative h-8 px-3"
                                >
                                  {activeAttackBssids.has(network.bssid) ? (
                                    <>
                                      <Loader2 className="h-3 w-3 animate-spin mr-2" />
                                      Attacking
                                    </>
                                  ) : (
                                    "Attack"
                                  )}
                                </Button>

                                {/* 2. زرار الـ Trust (اللي كان ضايع) */}
                                {!isTrusted && (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    disabled={isTrusting}
                                    onClick={() => handleTrust(network)}
                                    className="h-8 px-3 border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.1)]"
                                  >
                                    {isTrusting ? (
                                      <Loader2 className="h-3 w-3 animate-spin" />
                                    ) : (
                                      <>
                                        <Shield className="h-3 w-3 mr-1.5" />
                                        Trust
                                      </>
                                    )}
                                  </Button>
                                )}

                                {/* 3. علامة صح لو الشبكة موثوقة فعلاً */}
                                {isTrusted && (
                                  <div className="flex items-center gap-1.5 text-emerald-500 bg-emerald-500/10 px-2 py-1 rounded-md border border-emerald-500/20">
                                    <CheckCircle2 className="h-4 w-4" />
                                    <span className="text-[10px] font-bold uppercase tracking-wider">Trusted</span>
                                  </div>
                                )}
                            </div>
                          </td>
                        </tr>
                        );
                      })}
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