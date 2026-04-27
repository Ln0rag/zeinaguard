"use client";

import React, { useState, useEffect, useMemo } from "react";
import { 
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow 
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  ShieldBan, Trash2, Activity, Search, Lock, Unlock, Copy, AlertTriangle, Clock
} from "lucide-react";
import { useSocket } from "@/hooks/use-socket"; 
import { useToast } from "@/hooks/use-toast"; 

export interface ThreatEvent {
  id: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  sourceMac: string;
  ssid: string;
  signal: number; 
  packets: number;
  detectedAt: string;
  isEncrypted: boolean;
  channel: number;
  sensorId: number;
}

function formatRelativeTime(timestamp: string) {
  if (!timestamp) return "Unknown";

  let safeTimestamp = timestamp;
  if (!safeTimestamp.includes('T') && safeTimestamp.includes(' ')) {
    safeTimestamp = safeTimestamp.replace(' ', 'T');
  }
  if (!safeTimestamp.endsWith('Z') && !safeTimestamp.includes('+') && !safeTimestamp.match(/-\d{2}:\d{2}$/)) {
    safeTimestamp += 'Z';
  }

  const now = new Date().getTime();
  const then = new Date(safeTimestamp).getTime();

  if (isNaN(then)) return timestamp;

  const deltaSeconds = Math.max(0, Math.floor((now - then) / 1000));

  if (deltaSeconds < 5) return "Just now";
  if (deltaSeconds < 60) return `${deltaSeconds}s ago`;

  const deltaMinutes = Math.floor(deltaSeconds / 60);
  if (deltaMinutes < 60) {
    const remainingSeconds = deltaSeconds % 60;
    return remainingSeconds > 0 ? `${deltaMinutes}m ${remainingSeconds}s ago` : `${deltaMinutes}m ago`;
  }

  const deltaHours = Math.floor(deltaMinutes / 60);
  if (deltaHours < 24) {
    const remainingMinutes = deltaMinutes % 60;
    return remainingMinutes > 0 ? `${deltaHours}h ${remainingMinutes}m ago` : `${deltaHours}h ago`;
  }

  const deltaDays = Math.floor(deltaHours / 24);
  if (deltaDays < 7) {
    const remainingHours = deltaHours % 24;
    return remainingHours > 0 ? `${deltaDays}d ${remainingHours}h ago` : `${deltaDays}d ago`;
  }

  return new Date(then).toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });
}

function parseSignal(val: any): number {
  if (typeof val === 'number') return val;
  if (val === null || val === undefined) return -90;
  const parsed = parseInt(String(val).replace(/[^\d-]/g, ''));
  return isNaN(parsed) ? -90 : parsed;
}

const SignalBars = ({ signal }: { signal: number }) => {
  const bars = 5;
  const numSignal = signal;
  
  const activeBars = numSignal >= -50 ? 5 : numSignal >= -65 ? 4 : numSignal >= -80 ? 3 : numSignal >= -90 ? 2 : 1;
  
  const getColor = () => {
    if (activeBars >= 4) return "bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]";
    if (activeBars === 3) return "bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.6)]";
    if (activeBars === 2) return "bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.6)]";
    return "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]";
  };

  return (
    <div className="flex items-end space-x-[2px] h-4">
      {[...Array(bars)].map((_, i) => (
        <div 
          key={i} 
          className={`w-1.5 rounded-sm transition-all duration-300 ${i < activeBars ? getColor() : "bg-slate-700 h-1"}`}
          style={{ height: i < activeBars ? `${(i + 1) * 20}%` : '20%' }}
        />
      ))}
      <span className="text-xs text-slate-400 ml-2">{numSignal} dBm</span>
    </div>
  );
};

export function ThreatFeed() {
  const { socket, isConnected, sendAttackCommand } = useSocket();
  const { toast } = useToast();
  const [filter, setFilter] = useState<"ALL" | "HIGH" | "MEDIUM" | "LOW">("ALL");
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

  const formatThreatData = (data: any): ThreatEvent => {
    const rawSev = (data.severity || "info").toLowerCase();
    const sev = (rawSev === "critical" || rawSev === "high") ? "HIGH" : (rawSev === "medium" || rawSev === "suspicious") ? "MEDIUM" : "LOW";

    return {
      id: String(data.threat_id || data.id || Math.random()),
      severity: sev,
      sourceMac: data.bssid || data.source_mac || "Unknown",
      ssid: data.ssid || "Hidden",
      signal: parseSignal(data.signal ?? data.signal_strength),
      packets: Number(data.packet_count || 0),
      detectedAt: data.timestamp || data.created_at || new Date().toISOString(),
      isEncrypted: !!data.encryption && data.encryption !== "OPEN",
      channel: Number(data.channel || 6),
      sensorId: Number(data.sensor_id || data.detected_by || 1)
    };
  };

  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        // Fetches from the correct dashboard endpoint for live signals
        const [threatRes, netRes] = await Promise.all([
          fetch("http://localhost:5000/api/threats/?resolved=false&limit=100"),
          fetch("http://localhost:5000/networks/active").catch(() => null)
        ]);

        const signalMap = new Map<string, number>();

        if (netRes && netRes.ok) {
          const netJson = await netRes.json();
          const activeNetworks = netJson.data || netJson.networks || [];
          if (Array.isArray(activeNetworks)) {
            activeNetworks.forEach((net: any) => {
              if (net.bssid) {
                signalMap.set(String(net.bssid).toUpperCase(), parseSignal(net.signal ?? net.signal_strength));
              }
            });
          }
        }

        if (threatRes.ok) {
          const json = await threatRes.json();
          if (json.data) {
            const uniqueThreatsMap = new Map();
            json.data.forEach((item: any) => {
              const formatted = formatThreatData(item);
              
              const liveSignal = signalMap.get(formatted.sourceMac.toUpperCase());
              if (liveSignal !== undefined) {
                formatted.signal = liveSignal;
              }

              if (!uniqueThreatsMap.has(formatted.sourceMac)) {
                uniqueThreatsMap.set(formatted.sourceMac, formatted);
              }
            });
            setThreats(Array.from(uniqueThreatsMap.values()));
          }
        }
      } catch (error) {
        console.error("Failed to load initial data", error);
      }
    };
    fetchInitialData();
  }, []);

  useEffect(() => {
    if (!socket) return;

    const handleThreat = (data: any) => {
      const newThreat = formatThreatData(data);
      
      setThreats((prev) => {
        const existingIndex = prev.findIndex(t => t.sourceMac === newThreat.sourceMac);
        if (existingIndex >= 0) {
          const updatedThreats = [...prev];
          updatedThreats[existingIndex] = { 
            ...updatedThreats[existingIndex], 
            signal: newThreat.signal,
            detectedAt: newThreat.detectedAt, 
            severity: newThreat.severity 
          };
          const [movedItem] = updatedThreats.splice(existingIndex, 1);
          return [movedItem, ...updatedThreats];
        }
        return [newThreat, ...prev].slice(0, 100);
      });
      
      if (newThreat.severity === "HIGH") {
        toast({
          variant: "destructive",
          title: "Critical Threat Detected!",
          description: `Target: ${newThreat.sourceMac}`,
        });
      }
    };

    const updateLiveSignal = (payload: any) => {
      const bssid = String(payload.bssid || "").toUpperCase();
      const newSignal = parseSignal(payload.signal ?? payload.signal_strength);
      
      if (!bssid || newSignal === -90) return;

      setThreats((prev) => {
        const existingIndex = prev.findIndex(t => t.sourceMac.toUpperCase() === bssid);
        if (existingIndex >= 0 && prev[existingIndex].signal !== newSignal) {
          const updated = [...prev];
          updated[existingIndex] = { ...updated[existingIndex], signal: newSignal };
          return updated;
        }
        return prev;
      });
    };

    // Listen to bulk snapshots from the socket as well
    const handleNetworkSnapshot = (payload: any) => {
      const networks = Array.isArray(payload) ? payload : (payload?.data || []);
      if (!Array.isArray(networks)) return;
      
      setThreats((prev) => {
        let changed = false;
        const updated = [...prev];
        
        networks.forEach(net => {
          const bssid = String(net.bssid || "").toUpperCase();
          const newSignal = parseSignal(net.signal ?? net.signal_strength);
          
          const index = updated.findIndex(t => t.sourceMac.toUpperCase() === bssid);
          if (index >= 0 && updated[index].signal !== newSignal) {
            updated[index] = { ...updated[index], signal: newSignal };
            changed = true;
          }
        });
        
        return changed ? updated : prev;
      });
    };

    socket.on("threat_detected", handleThreat);
    socket.on("live_scan", updateLiveSignal);
    socket.on("network_update", updateLiveSignal);
    socket.on("networks_snapshot", handleNetworkSnapshot);

    return () => {
      socket.off("threat_detected", handleThreat);
      socket.off("live_scan", updateLiveSignal);
      socket.off("network_update", updateLiveSignal);
      socket.off("networks_snapshot", handleNetworkSnapshot);
    };
  }, [socket, toast]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied!", description: `${text} copied to clipboard.`, duration: 2000 });
  };

  const handleIsolate = async (threat: ThreatEvent) => {
    if (!isConnected) return;
    try {
      sendAttackCommand({
        sensor_id: threat.sensorId || 1,
        bssid: threat.sourceMac,
        target_bssid: threat.sourceMac,
        action: "deauth",
        channel: threat.channel || 1
      });
      toast({ title: "Isolating Host", description: `Deauth sent to ${threat.sourceMac}`, variant: "destructive" });
    } catch (e) {
      console.error(e);
    }
  };

  const handleDismiss = async (id: string) => {
    try {
      await fetch(`http://localhost:5000/api/threats/${id}/resolve`, { method: "POST" });
    } catch (e) {
      console.error(e);
    }
    setThreats((prev) => prev.filter((t) => t.id !== id));
  };

  const filteredThreats = useMemo(() => {
    return threats.filter((threat) => filter === "ALL" ? true : threat.severity === filter);
  }, [threats, filter]);

  return (
    <div className="space-y-6 w-full max-w-[1600px] mx-auto animate-in fade-in duration-500">
      
      <div className="flex items-center justify-between text-xs px-2 mb-2">
        <div className="flex items-center space-x-2">
          {isConnected ? (
            <span className="flex items-center text-green-400 font-medium tracking-wider uppercase">
              <span className="animate-ping h-2 w-2 rounded-full bg-green-500 mr-2"></span>
              Live Connection Active
            </span>
          ) : (
            <span className="text-red-500 font-medium tracking-wider uppercase">Connection Lost</span>
          )}
        </div>
        <div className="text-slate-400 flex items-center gap-2">
          <Activity className="w-4 h-4 text-emerald-400" />
          <span>Real-time Monitoring Active</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 bg-slate-900/60 backdrop-blur-md border border-slate-700/50 p-4 rounded-xl shadow-xl">
        <div className="flex flex-col justify-center">
          <h2 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-indigo-400">
            Real-Time Threat Feed
          </h2>
          <p className="text-sm text-slate-400">Monitoring real-time network anomalies</p>
        </div>

        <div className="flex justify-around items-center border-x border-slate-700/50 px-4">
          <div className="text-center">
            <p className="text-xs text-slate-400 uppercase tracking-wider mb-1">Active</p>
            <p className="text-2xl font-bold text-white">{threats.length}</p>
          </div>
          <div className="text-center">
            <p className="text-xs text-slate-400 uppercase tracking-wider mb-1">High Risk</p>
            <p className="text-2xl font-bold text-red-400">{threats.filter(t => t.severity === "HIGH").length}</p>
          </div>
        </div>
        
        <div className="flex items-center justify-end space-x-3">
          {(["ALL", "HIGH", "MEDIUM", "LOW"] as const).map((f) => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-4 py-1.5 rounded-full text-xs font-bold transition-all border ${
                filter === f ? "bg-blue-600/20 text-blue-400 border-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.5)]" : "bg-slate-800/50 text-slate-500 border-slate-700 hover:bg-slate-800"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-slate-700/50 bg-slate-900/40 backdrop-blur-sm overflow-hidden shadow-2xl">
        <Table>
          <TableHeader className="bg-slate-900/80 border-b border-slate-700/50">
            <TableRow>
              <TableHead className="text-slate-400 py-4">Severity</TableHead>
              <TableHead className="text-slate-400">Source MAC</TableHead>
              <TableHead className="text-slate-400">SSID</TableHead>
              <TableHead className="text-slate-400">Signal</TableHead>
              <TableHead className="text-slate-400">Last Seen</TableHead>
              <TableHead className="text-right text-slate-400">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredThreats.length === 0 ? (
              <TableRow><TableCell colSpan={6} className="h-64 text-center text-slate-500">Scanning Environment...</TableCell></TableRow>
            ) : (
              filteredThreats.map((threat) => (
                <TableRow key={threat.id} className="border-b border-slate-800/50 hover:bg-slate-800/40 transition-colors group">
                  <TableCell className="py-4">
                    <Badge variant="outline" className={`px-3 py-1 font-bold ${
                      threat.severity === "HIGH" ? "bg-red-500/10 border-red-500 text-red-500" :
                      threat.severity === "MEDIUM" ? "bg-orange-500/10 border-orange-500 text-orange-400" : "bg-yellow-500/10 border-yellow-500 text-yellow-400"
                    }`}>
                      {threat.severity}
                    </Badge>
                  </TableCell>
                  
                  {/* Restored Copy Button Logic */}
                  <TableCell>
                    <div className="flex items-center gap-2 group-hover:text-blue-300 transition-colors">
                      <span className="font-mono text-blue-400 tracking-wider">
                        {threat.sourceMac}
                      </span>
                      <button 
                        onClick={() => copyToClipboard(threat.sourceMac)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-500 hover:text-white"
                        title="Copy MAC Address"
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                    </div>
                  </TableCell>

                  <TableCell>
                    <div className="flex items-center gap-2">
                      {threat.isEncrypted ? <Lock className="w-4 h-4 text-green-500" /> : <Unlock className="w-4 h-4 text-red-400" />}
                      <span className={`font-medium ${threat.ssid === "Unknown" || !threat.ssid ? "text-slate-500 italic" : "text-slate-200"}`}>
                        {threat.ssid || "Hidden"}
                      </span>
                    </div>
                  </TableCell>
                  
                  <TableCell><SignalBars signal={threat.signal} /></TableCell>
                  
                  <TableCell>
                    <div className="flex items-center text-slate-400 text-xs font-mono">
                      <Clock className="w-3 h-3 mr-1 text-blue-400" />
                      {formatRelativeTime(threat.detectedAt)}
                    </div>
                  </TableCell>
                  
                  <TableCell className="text-right">
                    <div className="flex justify-end space-x-2 opacity-80 group-hover:opacity-100 transition-opacity">
                      {threat.severity === "HIGH" && (
                        <Button size="sm" variant="destructive" className="bg-red-600/20 text-red-500 border-red-900/50 hover:bg-red-600 hover:text-white transition-all" onClick={() => handleIsolate(threat)}>
                          <ShieldBan className="w-4 h-4 mr-2" /> Isolate
                        </Button>
                      )}
                      <Button size="sm" variant="ghost" className="text-slate-500 hover:text-white" onClick={() => handleDismiss(threat.id)}>
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}