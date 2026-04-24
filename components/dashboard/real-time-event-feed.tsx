'use client';

import { useEffect, useState, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Activity, AlertCircle, CheckCircle2, Clock, Zap, Shield } from 'lucide-react';
import { toast } from 'sonner';
import { useSocket } from '@/hooks/use-socket';

interface ThreatEvent {
  id: number;
  threat_type: string;
  ssid: string;
  source_mac: string;
  signal_strength: number;
  detected_by: number;
  timestamp: string;
  detected_by_sensor: string | number;
  status: 'detected' | 'resolved' | 'mitigated';
  is_resolved: boolean;
  action_taken: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export function RealTimeEventFeed() {
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [blockingId, setBlockingId] = useState<number | null>(null);

  // WebSocket real-time updates
  useSocket({
    onThreatEvent: useCallback((event: any) => {
      const newEvent: ThreatEvent = {
        id: event.data?.id || Date.now(),
        threat_type: event.data?.threat_type || 'Unknown',
        ssid: event.data?.ssid || 'N/A',
        source_mac: event.data?.source_mac || 'N/A',
        signal_strength: event.data?.signal_strength || 0,
        detected_by: event.data?.detected_by || 0,
        timestamp: event.timestamp || new Date().toISOString(),
        detected_by_sensor: event.data?.detected_by_sensor || 'Unknown',
        status: 'detected' as const,
        is_resolved: false,
        action_taken: 'Detected',
        severity: (event.severity || 'high') as ThreatEvent['severity'],
      };
      setEvents(prev => [newEvent, ...prev.slice(0, 9)]);
    }, []),
  });

  // Fetch initial events
  useEffect(() => {
    const fetchEvents = async () => {
      try {
        setLoading(true);
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/api/dashboard/threat-events?limit=10`,
          { headers: { 'Content-Type': 'application/json' } }
        );

        if (!response.ok) throw new Error('Failed to fetch threat events');
        const data = await response.json();
        setEvents(Array.isArray(data.events) ? data.events : []);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load events');
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
    const interval = setInterval(fetchEvents, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleBlockThreat = async (event: ThreatEvent) => {
    try {
      setBlockingId(event.id);
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/api/threats/${event.id}/block`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mac_address: event.source_mac,
            threat_type: event.threat_type,
            action: 'deauth',
          }),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to block threat');
      }

      const result = await response.json();
      
      // Update event status
      setEvents(prev =>
        prev.map(e =>
          e.id === event.id
            ? { ...e, is_resolved: true, action_taken: 'Blocked - Deauth sent' }
            : e
        )
      );

      toast.success('Threat Blocked', {
        description: `Deauth command sent to ${event.source_mac}`,
        position: 'bottom-center',
      });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to block threat';
      toast.error('Block Failed', {
        description: errorMsg,
        position: 'bottom-center',
      });
    } finally {
      setBlockingId(null);
    }
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'high':
        return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default:
        return 'text-blue-600 bg-blue-50 border-blue-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'resolved':
        return <CheckCircle2 className="w-4 h-4 text-green-500" />;
      case 'mitigated':
        return <CheckCircle2 className="w-4 h-4 text-blue-500" />;
      default:
        return <AlertCircle className="w-4 h-4 text-red-500" />;
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <AlertCircle className="w-4 h-4" />;
      case 'high':
        return <Zap className="w-4 h-4" />;
      case 'medium':
        return <Activity className="w-4 h-4" />;
      default:
        return <Shield className="w-4 h-4" />;
    }
  };

  if (error) {
    return (
      <Card className="border-destructive/50 bg-destructive/5">
        <CardHeader>
          <CardTitle className="text-destructive flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Event Feed Error
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
    <Card className="bg-slate-800 border-slate-700">
      <CardHeader>
        <CardTitle className="text-white flex items-center gap-2">
          <Activity className="w-5 h-5 text-yellow-400" />
          Real-Time Event Feed
        </CardTitle>
        <CardDescription className="text-slate-400">
          Latest threat detection and mitigation events
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="h-48 flex items-center justify-center text-slate-400">
            <Activity className="w-5 h-5 animate-spin mr-2" />
            Loading events...
          </div>
        ) : events.length === 0 ? (
          <div className="h-48 flex items-center justify-center text-slate-400">
            No recent events
          </div>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {events.map((event) => (
              <div
                key={event.id}
                className="p-3 bg-slate-700/40 rounded-lg border border-slate-600 hover:bg-slate-700/60 transition-colors"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs px-2 py-1 rounded font-semibold whitespace-nowrap ${getSeverityColor(event.severity)}`}>
                        {event.severity.toUpperCase()}
                      </span>
                      <span className="text-xs text-slate-400 truncate">
                        {new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                    </div>
                    <h5 className="font-medium text-white text-sm capitalize mb-1">
                      {event.threat_type.replace(/_/g, ' ')}
                    </h5>
                    <div className="text-xs text-slate-400 space-y-1">
                      <p>
                        <span className="text-slate-500">SSID:</span> {event.ssid}
                      </p>
                      <p>
                        <span className="text-slate-500">MAC:</span> {event.source_mac}
                      </p>
                      <p>
                        <span className="text-slate-500">Sensor:</span> {event.detected_by_sensor}
                      </p>
                      {event.action_taken && (
                        <p>
                          <span className="text-slate-500">Action:</span> {event.action_taken}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    {getStatusIcon(event.status)}
                    <span className={`text-xs px-2 py-1 rounded font-semibold whitespace-nowrap ${
                      event.status === 'resolved'
                        ? 'bg-green-900 text-green-100'
                        : event.status === 'mitigated'
                        ? 'bg-blue-900 text-blue-100'
                        : 'bg-red-900 text-red-100'
                    }`}>
                      {event.status.toUpperCase()}
                    </span>
                    <span className="text-xs text-yellow-400 font-semibold">
                      {event.signal_strength}%
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
