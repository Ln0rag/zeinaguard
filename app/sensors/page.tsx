"use client";

import React, { useState, useEffect, useRef } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Cpu, HardDrive, Activity } from "lucide-react";
import { useSocket } from "@/hooks/use-socket";
import { useSensorStore } from "@/hooks/use-sensor-store";

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

function formatUptime(seconds: number) {
  if (!seconds || seconds <= 0) return "0s";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  return `${h}h ${m}m`;
}

export default function SensorsPage() {
  const [sensors, setSensors] = useState<SensorData[]>([]);
  const [now, setNow] = useState(Date.now());
  const addLog = useSensorStore((state) => state.addLog);

  const { isConnected } = useSocket({
    onSensorSnapshot: (event: any) => {
      const rawData = event?.data || event;
      const sensorList = Array.isArray(rawData) ? rawData : Object.values(rawData);
      
      setSensors(sensorList.map(s => {
        const targetId = Number(s.sensor_id || s.id || 0);
        if (s.message) addLog(targetId, s.message);
        return normalizeSensor(s);
      }));
    },
    onSensorStatusUpdate: (event: any) => {
      const rawData = event?.data || event;
      const targetId = Number(rawData.sensor_id || rawData.id || 0);

      setSensors((prev) => {
        const index = prev.findIndex(s => s.sensor_id === targetId);
        if (index >= 0) {
          const oldSensor = prev[index];
          const newSensors = [...prev];
          newSensors[index] = { ...oldSensor, ...normalizeSensor(rawData) };
          return newSensors;
        }
        return [...prev, normalizeSensor(rawData)];
      });
    },
  });

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

  const normalizeSensor = (data: any): SensorData => {
    const newMsg = data.message || "No activity reported";
    
    const isHardwareOffline = 
      newMsg.toLowerCase().includes("disconnected") || 
      newMsg.toLowerCase().includes("error") ||
      newMsg.toLowerCase().includes("physically removed") ||
      newMsg.toLowerCase().includes("lost") ||
      newMsg.toLowerCase().includes("down") ||
      newMsg.toLowerCase().includes("no such device") ||
      newMsg.toLowerCase().includes("errno 19") ||
      (data.status || data.sensor_status || "").toLowerCase() === "error";

    const resolvedStatus = isHardwareOffline 
      ? "offline" 
      : (["monitoring", "online", "starting"].includes((data.status || data.sensor_status || "offline").toLowerCase()) ? "online" : "offline");

    return {
      sensor_id: Number(data.sensor_id || data.id || 0),
      status: resolvedStatus,
      signal_strength: Number(data.signal_strength || data.signal || -90),
      cpu_usage: Number(data.cpu_usage || data.cpu || 0),
      memory_usage: Number(data.memory_usage || data.memory || 0),
      uptime: Number(data.uptime || data.uptime_seconds || 0),
      last_seen: data.last_seen || data.last_heartbeat || new Date().toISOString(),
      hostname: data.hostname || data.name || "Unknown Sensor",
      interface: data.interface || "N/A",
      message: newMsg,
    };
  };

  return (
    <div className="flex-1 space-y-8 p-6 md:px-10 md:pt-4 md:pb-10 min-h-screen bg-slate-900 text-white font-sans">
      
      {/* Header Section */}
      <div className="flex items-center justify-between gap-4 border-b border-emerald-500/10 pb-4">
        <div className="text-emerald-400 drop-shadow-[0_0_10px_rgba(52,211,153,0.7)] text-xl font-bold tracking-tight whitespace-nowrap">
          Sensors Management
        </div>
        <div className="flex items-center gap-3">
          {isConnected && sensors.some(s => s.status === "online") ? (
            <span className="text-emerald-400 font-medium tracking-wider uppercase flex items-center drop-shadow-[0_0_5px_rgba(52,211,153,0.5)] text-xs">
              <span className="animate-ping h-2 w-2 rounded-full bg-emerald-500 mr-2"></span> Fleet Online
            </span>
          ) : (
            <span className="text-red-500 font-medium tracking-wider uppercase text-xs">Fleet Offline</span>
          )}
        </div>
      </div>

      <div className="flex flex-col gap-8">
        {sensors.map((sensor) => (
          <SensorRow key={sensor.sensor_id} sensor={sensor} />
        ))}
      </div>
    </div>
  );
}

function SensorRow({ sensor }: { sensor: SensorData }) {
  const logsEndRef = useRef<HTMLDivElement>(null);
  
  const logs = useSensorStore((state) => state.logs[sensor.sensor_id] || []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <Card className="bg-slate-900 border-emerald-500/20 shadow-[0_0_15px_rgba(0,0,0,0.4)] overflow-hidden">
      <CardContent className="p-0">
        <div className="flex flex-col lg:flex-row min-h-[350px]">
          
          <div className="w-full lg:w-[350px] p-6 border-b lg:border-b-0 lg:border-r border-emerald-500/10 bg-emerald-950/5">
            <div className="flex justify-between items-center mb-8">
              <div className="flex flex-col">
                <span className="text-sm text-emerald-500/60 font-mono tracking-wider">ID: #{sensor.sensor_id}</span>
                <h3 className="text-emerald-100 font-bold text-2xl">{sensor.hostname}</h3>
              </div>
              <Badge variant="outline" className={`px-4 py-1.5 text-sm font-bold ${sensor.status === "online" ? "border-emerald-500/50 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.1)]" : "border-red-500/50 text-red-500 shadow-[0_0_10px_rgba(239,68,68,0.3)] bg-red-950/20"}`}>
                {sensor.status.toUpperCase()}
              </Badge>
            </div>

            <div className="space-y-6">
              <StatBar label="CPU" value={sensor.cpu_usage} icon={<Cpu className="w-6 h-6" />} color="bg-emerald-500" />
              <StatBar label="RAM" value={sensor.memory_usage} icon={<HardDrive className="w-6 h-6" />} color="bg-orange-500" />
            </div>

            <div className="mt-8 pt-6 border-t border-emerald-500/10 space-y-4">
              <div className="flex justify-between font-mono items-center">
                <span className="text-slate-500 text-base">Interface</span>
                <span className="text-emerald-400 font-bold text-lg">{sensor.interface}</span>
              </div>
              <div className="flex justify-between font-mono items-center">
                <span className="text-slate-500 text-base">Uptime</span>
                <span className="text-emerald-50/80 text-lg">{formatUptime(sensor.uptime)}</span>
              </div>
            </div>
          </div>

          <div className="flex-1 flex flex-col bg-black/20 p-6 justify-center">
            <div className="flex items-center gap-3 mb-2">
              <Activity className="w-5 h-5 text-emerald-500 animate-pulse" />
              <span className="text-[10px] uppercase font-bold tracking-widest text-emerald-500/70">Live Activity Log</span>
            </div>
            
            <div className="bg-black/40 rounded-lg p-6 font-mono text-base border border-emerald-500/10 shadow-inner h-[320px] overflow-y-auto flex flex-col custom-scrollbar">
               <div className="mt-auto">
                 {logs.map((log, idx) => (
                   <div key={idx} className={`flex gap-3 mt-1 ${idx === logs.length - 1 ? 'text-emerald-400 font-bold drop-shadow-[0_0_2px_rgba(52,211,153,0.8)]' : 'text-emerald-300/80'}`}>
                      <span className="text-emerald-500/50 font-bold select-none">{">"}</span>
                      <span className="leading-relaxed break-words">{log}</span>
                   </div>
                 ))}
                 {logs.length === 0 && (
                   <div className="flex gap-3 text-emerald-500/50">
                      <span className="text-emerald-500/30 select-none">{">"}</span>
                      <span className="leading-relaxed">Waiting for data...</span>
                   </div>
                 )}
                 <div ref={logsEndRef} />
               </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatBar({ label, value, icon, color }: any) {
  return (
    <div className="space-y-3">
      <div className="flex justify-between font-mono items-center">
        <span className="text-slate-400 flex items-center gap-3 text-base">{icon} {label}</span>
        <span className="text-emerald-400 font-bold text-xl drop-shadow-[0_0_2px_rgba(52,211,153,0.5)]">{value.toFixed(1)}%</span>
      </div>
      <div className="h-2.5 w-full bg-emerald-950/40 rounded-full overflow-hidden border border-emerald-500/10 shadow-inner">
        <div className={`h-full ${color} transition-all duration-1000 shadow-[0_0_8px_rgba(16,185,129,0.6)]`} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}
