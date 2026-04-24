'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertCircle, Wifi, Cpu, HardDrive, AlertTriangle } from 'lucide-react';
interface SensorMetric {
  sensor_id: number;
  name: string;
  status: 'online' | 'offline' | 'degraded';
  signal_strength: number;
  cpu_usage: number;
  memory_usage: number;
  threat_count: number;
  last_seen: string;
}

export function SensorHeatmap() {
  const [sensors, setSensors] = useState<SensorMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchSensorMetrics = async () => {
      try {
        setLoading(true);
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/api/sensors/health`,
          { headers: { 'Content-Type': 'application/json' } }
        );

        if (!response.ok) throw new Error('Failed to fetch sensor metrics');
        const data = await response.json();
        setSensors(Array.isArray(data.sensors) ? data.sensors : []);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load sensor metrics');
      } finally {
        setLoading(false);
      }
    };

    fetchSensorMetrics();
    const interval = setInterval(fetchSensorMetrics, 15000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string): { text: string; bg: string; indicator: string } => {
    switch (status) {
      case 'online':
        return { text: 'text-green-600', bg: 'bg-green-50', indicator: 'bg-green-500' };
      case 'degraded':
        return { text: 'text-yellow-600', bg: 'bg-yellow-50', indicator: 'bg-yellow-500' };
      case 'offline':
        return { text: 'text-red-600', bg: 'bg-red-50', indicator: 'bg-red-500' };
      default:
        return { text: 'text-gray-600', bg: 'bg-gray-50', indicator: 'bg-gray-500' };
    }
  };

  const getUsageColor = (usage: number): string => {
    if (usage >= 80) return 'text-red-600';
    if (usage >= 60) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getUsageBg = (usage: number): string => {
    if (usage >= 80) return 'bg-red-500';
    if (usage >= 60) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  if (error) {
    return (
      <Card className="border-destructive/50 bg-destructive/5">
        <CardHeader>
          <CardTitle className="text-destructive flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Sensor Health Error
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-card border-border">
      <CardHeader>
        <CardTitle className="text-foreground flex items-center gap-2">
          <Wifi className="w-5 h-5 text-blue-500" />
          Sensor Network Health
        </CardTitle>
        <CardDescription>Real-time sensor status and performance metrics</CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
          </div>
        ) : sensors.length > 0 ? (
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {sensors.map((sensor) => {
              const statusColor = getStatusColor(sensor.status);
              const cpuColor = getUsageColor(sensor.cpu_usage);
              const memColor = getUsageColor(sensor.memory_usage);

              return (
                <div
                  key={sensor.sensor_id}
                  className={`p-3 rounded-lg border ${statusColor.bg} ${
                    statusColor.text.replace('text-', 'border-').split('-')[0]
                  }-200`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-start gap-2 flex-1">
                      <div className={`w-3 h-3 rounded-full mt-1 flex-shrink-0 ${statusColor.indicator}`} />
                      <div className="flex-1 min-w-0">
                        <h4 className={`font-semibold text-sm ${statusColor.text}`}>
                          {sensor.name}
                        </h4>
                        <p className="text-xs text-foreground/60 mt-1">
                          ID: {sensor.sensor_id} | Signal: {sensor.signal_strength} dBm
                        </p>
                        <div className="grid grid-cols-2 gap-2 mt-2 text-xs">
                          <div className="flex items-center gap-1">
                            <Cpu className={`w-3 h-3 ${cpuColor}`} />
                            <span>CPU: {sensor.cpu_usage}%</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <HardDrive className={`w-3 h-3 ${memColor}`} />
                            <span>Mem: {sensor.memory_usage}%</span>
                          </div>
                        </div>
                        <div className="mt-2 flex items-center gap-1 text-xs text-foreground/60">
                          <AlertTriangle className="w-3 h-3" />
                          Threats: {sensor.threat_count}
                        </div>
                      </div>
                    </div>
                    <div className="flex-shrink-0 text-right">
                      <div className={`text-xs font-semibold ${statusColor.text}`}>
                        {sensor.status.charAt(0).toUpperCase() + sensor.status.slice(1)}
                      </div>
                      <div className="text-xs text-foreground/60 mt-1">
                        {new Date(sensor.last_seen).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                  <div className="mt-2 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-foreground/60">CPU Load</span>
                      <span className={cpuColor}>{sensor.cpu_usage}%</span>
                    </div>
                    <div className="w-full bg-foreground/10 rounded-full h-1 overflow-hidden">
                      <div
                        className={`h-full ${getUsageBg(sensor.cpu_usage)}`}
                        style={{ width: `${sensor.cpu_usage}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between text-xs mt-2">
                      <span className="text-foreground/60">Memory</span>
                      <span className={memColor}>{sensor.memory_usage}%</span>
                    </div>
                    <div className="w-full bg-foreground/10 rounded-full h-1 overflow-hidden">
                      <div
                        className={`h-full ${getUsageBg(sensor.memory_usage)}`}
                        style={{ width: `${sensor.memory_usage}%` }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-8 text-foreground/60">
            <Wifi className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No sensors available</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
