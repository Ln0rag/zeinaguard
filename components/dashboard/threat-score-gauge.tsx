'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Cpu, Activity, Shield, Wifi, AlertCircle } from 'lucide-react';
interface SystemMetrics {
  network_health: number;
  detection_efficiency: number;
  mitigation_rate: number;
  sensor_reliability: number;
  timestamp: string;
}

export function ThreatScoreGauge() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        setLoading(true);
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/api/dashboard/system-metrics`,
          { headers: { 'Content-Type': 'application/json' } }
        );

        if (!response.ok) throw new Error('Failed to fetch system metrics');
        const data = await response.json();
        setMetrics(data.metrics);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load metrics');
      } finally {
        setLoading(false);
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 30000);
    return () => clearInterval(interval);
  }, []);

  const getMetricColor = (value: number): string => {
    if (value >= 90) return 'text-green-500';
    if (value >= 70) return 'text-blue-500';
    if (value >= 50) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getMetricBgColor = (value: number): string => {
    if (value >= 90) return 'bg-green-500/10';
    if (value >= 70) return 'bg-blue-500/10';
    if (value >= 50) return 'bg-yellow-500/10';
    return 'bg-red-500/10';
  };

  const GaugeDisplay = ({ icon: Icon, label, value }: { icon: any; label: string; value: number }) => (
    <div className="flex flex-col items-center gap-2">
      <div className={`p-3 rounded-lg ${getMetricBgColor(value)}`}>
        <Icon className={`w-6 h-6 ${getMetricColor(value)}`} />
      </div>
      <span className="text-xs font-medium text-foreground/60">{label}</span>
      <span className={`text-2xl font-bold ${getMetricColor(value)}`}>
        {value}%
      </span>
    </div>
  );

  if (error) {
    return (
      <Card className="border-destructive/50 bg-destructive/5">
        <CardHeader>
          <CardTitle className="text-destructive flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            System Metrics Error
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
        <CardTitle className="text-foreground">System Performance</CardTitle>
        <CardDescription>Real-time operational effectiveness</CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
          </div>
        ) : metrics ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <GaugeDisplay icon={Wifi} label="Network Health" value={Math.round(metrics.network_health)} />
            <GaugeDisplay icon={Activity} label="Detection" value={Math.round(metrics.detection_efficiency)} />
            <GaugeDisplay icon={Shield} label="Mitigation" value={Math.round(metrics.mitigation_rate)} />
            <GaugeDisplay icon={Cpu} label="Sensor Reliability" value={Math.round(metrics.sensor_reliability)} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
