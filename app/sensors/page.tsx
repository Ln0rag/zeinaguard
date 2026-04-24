'use client';

import { useEffect, useState, useCallback } from 'react';
import { sensorsAPI } from '@/lib/api';
import { Activity, Wifi, Signal, Clock } from 'lucide-react';

interface Sensor {
  id: number;
  hostname: string;
  location: string;
  status: 'online' | 'offline' | 'degraded';
  signal_strength: number;
  uptime_percent: number;
  last_seen: string;
  packet_count: number;
  coverage_area: string;
}

function normalizeSensor(raw: Record<string, unknown>): Sensor {
  return {
    id: Number(raw.id) || 0,
    hostname: String(raw.hostname ?? raw.name ?? ''),
    location: String(raw.location ?? ''),
    status: (raw.status as Sensor['status']) ?? 'offline',
    signal_strength: Number(raw.signal_strength) ?? -70,
    uptime_percent: Number(raw.uptime_percent) ?? 100,
    last_seen: String(raw.last_seen ?? raw.last_heartbeat ?? new Date().toISOString()),
    packet_count: Number(raw.packet_count) ?? 0,
    coverage_area: String(raw.coverage_area ?? 'N/A'),
  };
}

export default function SensorsPage() {
  const [sensors, setSensors] = useState<Sensor[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSensors = useCallback(async () => {
    try {
      setError(null);
      setLoading(true);
      const data = await sensorsAPI.getSensors();
      const list = Array.isArray(data) ? data : [];
      setSensors(list.map((item: unknown) => normalizeSensor(item as Record<string, unknown>)));
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch sensors';
      setError(msg);
      setSensors([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSensors();
    const interval = setInterval(fetchSensors, 5000);
    return () => clearInterval(interval);
  }, [fetchSensors]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'bg-green-900 text-green-100';
      case 'offline':
        return 'bg-red-900 text-red-100';
      case 'degraded':
        return 'bg-yellow-900 text-yellow-100';
      default:
        return 'bg-slate-700 text-slate-100';
    }
  };

  const getSignalIndicator = (strength: number) => {
    if (strength >= -40) return 'Excellent';
    if (strength >= -55) return 'Good';
    if (strength >= -70) return 'Fair';
    return 'Poor';
  };

  if (loading && sensors.length === 0) {
    return (
      <div className="min-h-screen bg-slate-900 p-8 flex items-center justify-center">
        <div className="text-slate-300">Loading sensors...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-slate-900 p-8 flex items-center justify-center">
        <div className="text-center max-w-md">
          <Wifi className="w-16 h-16 text-amber-500/50 mx-auto mb-4" />
          <p className="text-slate-300 font-medium mb-2">Unable to load sensors</p>
          <p className="text-slate-500 text-sm mb-4">{error}</p>
          <button
            onClick={() => fetchSensors()}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white flex items-center gap-3">
            <Wifi className="w-10 h-10 text-blue-500" />
            Sensor Management
          </h1>
          <p className="text-slate-400 mt-2">
            Manage and monitor all wireless sensors
          </p>
        </div>

        {/* Sensor Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {sensors.map((sensor) => (
            <div
              key={sensor.id}
              className="bg-slate-800 border border-slate-700 rounded-lg p-6 hover:border-slate-600 transition-colors"
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-xl font-semibold text-white">
                    {sensor.hostname}
                  </h3>
                  <p className="text-sm text-slate-400">{sensor.location}</p>
                </div>
                <span
                  className={`text-xs font-medium px-3 py-1 rounded-full flex items-center gap-1 ${getStatusColor(
                    sensor.status
                  )}`}
                >
                  <Activity className="w-3 h-3" />
                  {sensor.status.toUpperCase()}
                </span>
              </div>

              {/* Signal Strength Sparkline */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm text-slate-400">Signal Strength</label>
                  <span className="text-sm font-medium text-blue-400">
                    {getSignalIndicator(sensor.signal_strength)}
                  </span>
                </div>
                <div className="bg-slate-700 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-blue-500 to-blue-600 h-full transition-all"
                    style={{
                      width: `${Math.min(100, (sensor.signal_strength + 100) * 1.2)}%`,
                    }}
                  />
                </div>
                <p className="text-xs text-slate-500 mt-1">{sensor.signal_strength} dBm</p>
              </div>

              {/* Uptime Indicator */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm text-slate-400 flex items-center gap-2">
                    <Clock className="w-3 h-3" />
                    Uptime
                  </label>
                  <span className="text-sm font-medium text-green-400">
                    {sensor.uptime_percent}%
                  </span>
                </div>
                <div className="bg-slate-700 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-green-500 to-green-600 h-full transition-all"
                    style={{ width: `${sensor.uptime_percent}%` }}
                  />
                </div>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-4 pt-4 border-t border-slate-700">
                <div>
                  <p className="text-xs text-slate-400">Packets</p>
                  <p className="text-lg font-semibold text-white">
                    {sensor.packet_count.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-slate-400">Coverage</p>
                  <p className="text-lg font-semibold text-white">
                    {sensor.coverage_area}
                  </p>
                </div>
              </div>

              {/* Last Seen */}
              <div className="mt-4 pt-4 border-t border-slate-700">
                <p className="text-xs text-slate-500">
                  Last seen: {new Date(sensor.last_seen).toLocaleTimeString()}
                </p>
              </div>
            </div>
          ))}
        </div>

        {sensors.length === 0 && !loading && (
          <div className="text-center py-12">
            <Wifi className="w-16 h-16 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400 text-lg">No sensors found</p>
          </div>
        )}
      </div>
    </div>
  );
}
