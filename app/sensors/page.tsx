"use client";

import React, { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Server, Cpu, HardDrive, Activity, WifiOff, Clock, TerminalSquare
} from "lucide-react";
import { useSocket } from "@/hooks/use-socket";

export interface SensorData {
  sensor_id: number;
  status: "online" | "offline";
  signal_strength: number;
  cpu_usage: number;
  memory_usage: number;
  uptime: number;
  last_seen: string;
  hostname: string;
  interface: string;
  message: string;
}

function formatRelativeTime(timestamp: string, now: number) {
  if (!timestamp) return "Unknown";
  let safeTimestamp = timestamp.replace(' ', 'T');
  if (!safeTimestamp.endsWith('Z') && !safeTimestamp.includes('+')) safeTimestamp += 'Z';
  const then = new Date(safeTimestamp).getTime();
  if (isNaN(then)) return "Unknown";
  const deltaSeconds = Math.max(0, Math.floor((now - then) / 1000));
  if (deltaSeconds < 5) return "Just now";
  if (deltaSeconds < 60) return `${deltaSeconds}s ago`;
  return `${Math.floor(deltaSeconds / 60)}m ago`;
}

function formatUptime(seconds: number) {
  if (!seconds || seconds <= 0) return "0s";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  return `${m}m ${s}s`;
}

export default function SensorsPage() {
  const [sensors, setSensors] = useState<SensorData[]>([]);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

  const normalizeSensor = (data: any): SensorData => {
    // Debugging: Check what the backend is actually sending
    console.log("Incoming Sensor Data:", data);
    
    return {
      sensor_id: Number(data.sensor_id || data.id || 0),
      status: (data.status || "offline").toLowerCase() as "online" | "offline",
      signal_strength: Number(data.signal_strength || data.signal || -90),
      cpu_usage: Number(data.cpu_usage || data.cpu || 0),
      memory_usage: Number(data.memory_usage || data.memory || 0),
      uptime: Number(data.uptime || data.uptime_seconds || 0),
      last_seen: data.last_seen || data.last_heartbeat || data.updated_at || new Date().toISOString(),
      hostname: data.hostname || data.name || "Unknown Sensor",
      interface: data.interface || "wlan0",
      message: data.message || "Running normally"
    };
  };

  const { isConnected } = useSocket({
    onSensorSnapshot: (event: any) => {
      const rawData = event?.data || event;
      const sensorList = Array.isArray(rawData) ? rawData : Object.values(rawData);
      setSensors(sensorList.map(normalizeSensor));
    },
    onSensorStatusUpdate: (event: any) => {
      const updatedData = normalizeSensor(event?.data || event);
      setSensors((prev) => {
        const index = prev.findIndex(s => s.sensor_id === updatedData.sensor_id);
        if (index >= 0) {
          const newSensors = [...prev];
          newSensors[index] = { ...newSensors[index], ...updatedData };
          return newSensors;
        }
        return [...prev, updatedData];
      });
    }
  });

  useEffect(() => {
    fetch("http://localhost:5000/api/sensors")
      .then(res => res.json())
      .then(json => {
        const rawData = json.data || json.sensors || json;
        const sensorList = Array.isArray(rawData) ? rawData : Object.values(rawData);
        setSensors(sensorList.map(normalizeSensor));
      })
      .catch(err => console.error("API Error:", err));
  }, []);

  const getLiveUptime = (sensor: SensorData) => {
    if (sensor.status !== "online") return "Offline";
    let safeTimestamp = sensor.last_seen.replace(' ', 'T');
    if (!safeTimestamp.endsWith('Z') && !safeTimestamp.includes('+')) safeTimestamp += 'Z';
    const lastSeenTime = new Date(safeTimestamp).getTime();
    const elapsedSeconds = isNaN(lastSeenTime) ? 0 : Math.max(0, Math.floor((now - lastSeenTime) / 1000));
    return formatUptime(sensor.uptime + elapsedSeconds);
  };

  return (
    <div className="flex-1 p-8 pt-6 w-full max-w-[1600px] mx-auto animate-in fade-in duration-500">
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center space-x-2">
          {isConnected ? (
            <span className="text-green-400 font-medium tracking-wider uppercase flex items-center">
              <span className="animate-ping h-2 w-2 rounded-full bg-green-500 mr-2"></span> Online
            </span>
          ) : (
            <span className="text-red-500 font-medium tracking-wider uppercase">Offline</span>
          )}
        </div>
        <div className="text-slate-400 flex items-center gap-2"><Server className="w-4 h-4" /> Hardware Telemetry</div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {sensors.map((sensor) => (
          <Card key={sensor.sensor_id} className="bg-slate-900/80 border-slate-700/50 shadow-xl group">
            <CardHeader className="bg-slate-950/50 border-b border-slate-800 pb-4">
              <div className="flex justify-between items-center">
                <CardTitle className="text-lg text-slate-200">{sensor.hostname}</CardTitle>
                <Badge variant="outline" className={sensor.status === "online" ? "border-green-500 text-green-400" : "border-red-500 text-red-400"}>
                  {sensor.status.toUpperCase()}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="pt-6 space-y-6">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400 flex items-center"><Cpu className="w-4 h-4 mr-2" /> CPU</span>
                  <span className="font-mono font-bold text-emerald-400">{sensor.cpu_usage.toFixed(1)}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-emerald-500 transition-all duration-500" style={{ width: `${sensor.cpu_usage}%` }} />
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400 flex items-center"><HardDrive className="w-4 h-4 mr-2" /> RAM</span>
                  <span className="font-mono font-bold text-orange-400">{sensor.memory_usage.toFixed(1)}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-orange-500 transition-all duration-500" style={{ width: `${sensor.memory_usage}%` }} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4 bg-slate-950/50 p-4 rounded-lg border border-slate-800">
                <div>
                  <div className="text-[10px] text-slate-500 uppercase flex items-center mb-1"><Clock className="w-3 h-3 mr-1" /> Uptime</div>
                  <div className="text-sm font-mono text-slate-200">{getLiveUptime(sensor)}</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 uppercase flex items-center mb-1"><TerminalSquare className="w-3 h-3 mr-1" /> Network</div>
                  <div className="text-sm font-mono text-blue-400">{sensor.interface} <span className="text-[10px] text-slate-500">{sensor.signal_strength}dBm</span></div>
                </div>
              </div>
              <div className="pt-4 flex justify-between text-[10px] text-slate-500 border-t border-slate-800">
                <span>{sensor.message}</span>
                <span>{formatRelativeTime(sensor.last_seen, now)}</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}