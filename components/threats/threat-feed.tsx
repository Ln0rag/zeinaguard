'use client';

import { useState, useEffect } from 'react';
import { useSocket, ThreatEvent } from '@/hooks/use-socket';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertTriangle, AlertCircle, WifiOff, Loader2 } from 'lucide-react';

interface ThreatItem extends ThreatEvent {
  id: string | number;
}

export function ThreatFeed() {
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [latestThreatTime, setLatestThreatTime] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Fetch initial threats from database
  const fetchInitialThreats = async () => {
    try {
      setLoading(true);
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';
      const response = await fetch(`${apiUrl}/api/threats/`);
      
      if (response.ok) {
        const result = await response.json();
        if (result.success && Array.isArray(result.data)) {
          // Map DB threats to the format expected by the feed
          const mappedThreats = result.data.map((t: any) => ({
            id: t.id,
            timestamp: t.created_at,
            severity: t.severity,
            data: {
              threat_type: t.threat_type,
              description: t.description,
              source_mac: t.source_mac,
              ssid: t.ssid,
              signal_strength: t.signal_strength || -70,
              packet_count: t.packet_count || 0,
              created_at: t.created_at
            }
          }));
          setThreats(mappedThreats);
        }
      }
    } catch (error) {
      console.error('Failed to fetch initial threats:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInitialThreats();
  }, []);

  const handleThreatEvent = (event: ThreatEvent) => {
    // Add threat to the list
    const threatItem: ThreatItem = {
      ...event,
      id: `${event.timestamp}-${Math.random()}`,
    };

    // Add to beginning of list (newest first)
    setThreats((prev) => [threatItem, ...prev].slice(0, 50));
    
    // Update latest threat time
    setLatestThreatTime(event.timestamp);

    // Visual feedback: flash the screen for critical threats
    if (event.severity === 'critical') {
      flashCriticalAlert();
    }
  };

  const { isConnected: isSocketConnected } = useSocket({
    onThreatEvent: handleThreatEvent,
  });

  useEffect(() => {
    setIsConnected(isSocketConnected());
  }, [isSocketConnected]);

  const flashCriticalAlert = () => {
    const body = document.body;
    const originalBg = body.style.backgroundColor;
    body.style.backgroundColor = '#7f1d1d'; // Red
    setTimeout(() => {
      body.style.backgroundColor = originalBg;
    }, 200);
    setTimeout(() => {
      body.style.backgroundColor = '#7f1d1d';
    }, 400);
    setTimeout(() => {
      body.style.backgroundColor = originalBg;
    }, 600);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-900 text-red-100 border-red-700';
      case 'high':
        return 'bg-orange-900 text-orange-100 border-orange-700';
      case 'medium':
        return 'bg-yellow-900 text-yellow-100 border-yellow-700';
      case 'low':
        return 'bg-blue-900 text-blue-100 border-blue-700';
      default:
        return 'bg-slate-700 text-slate-100 border-slate-600';
    }
  };

  const getSeverityIcon = (severity: string) => {
    const s = severity.toLowerCase();
    if (s === 'critical' || s === 'high') {
      return <AlertTriangle className="w-4 h-4" />;
    }
    return <AlertCircle className="w-4 h-4" />;
  };

  const getThreatTypeLabel = (threatType: string) => {
    return threatType
      .split('_')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  return (
    <div className="space-y-4">
      {/* Connection Status */}
      <Card className={`bg-${isConnected ? 'green' : 'red'}-900 border-${isConnected ? 'green' : 'red'}-700`}>
        <CardContent className="pt-6 flex items-center gap-3">
          {isConnected ? (
            <>
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
              <p className="text-green-100">WebSocket Connected - Ready for real-time threat events</p>
            </>
          ) : (
            <>
              <WifiOff className="w-4 h-4 text-red-400" />
              <p className="text-red-100">WebSocket Disconnected - Reconnecting...</p>
            </>
          )}
        </CardContent>
      </Card>

      {/* Latest Threat Alert */}
      {latestThreatTime && (
        <Alert className="bg-red-900 border-red-700">
          <AlertDescription className="text-red-100">
            Latest threat detected at {new Date(latestThreatTime).toLocaleTimeString()}
          </AlertDescription>
        </Alert>
      )}

      {/* Threat List Header */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <span>Security Threat Feed</span>
            <Badge variant="outline" className="ml-auto bg-slate-700 text-slate-100">
              {threats.length} total
            </Badge>
          </CardTitle>
          <CardDescription className="text-slate-400">
            Monitoring wireless infrastructure for anomalies
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Threat Items */}
      <div className="space-y-3">
        {loading ? (
          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="pt-6 text-center text-slate-400 flex flex-col items-center gap-2">
              <Loader2 className="w-8 h-8 animate-spin" />
              <p>Loading threat history...</p>
            </CardContent>
          </Card>
        ) : threats.length === 0 ? (
          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="pt-6 text-center text-slate-400">
              <p>No threats detected yet</p>
              <p className="text-sm mt-2">When threats are detected, they will appear here in real-time</p>
            </CardContent>
          </Card>
        ) : (
          threats.map((threat) => (
            <Card
              key={threat.id}
              className={`${getSeverityColor(threat.severity)} border-2`}
            >
              <CardContent className="pt-6">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3 flex-1">
                    {getSeverityIcon(threat.severity)}
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-semibold">
                          {getThreatTypeLabel(threat.data.threat_type)}
                        </h3>
                        <Badge variant="outline" className="text-xs">
                          {threat.severity.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-sm mb-2">{threat.data.description}</p>
                      <div className="text-xs space-y-1">
                        <p>Source MAC: {threat.data.source_mac}</p>
                        <p>SSID: {threat.data.ssid}</p>
                        <p>Signal Strength: {threat.data.signal_strength} dBm</p>
                        <p>Packets: {threat.data.packet_count}</p>
                        <p>Detected: {new Date(threat.data.created_at).toLocaleString()}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

    </div>
  );
}
