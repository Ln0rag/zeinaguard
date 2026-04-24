'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { threatsAPI } from '@/lib/api';

export function ThreatSimulator() {
  const [isSimulating, setIsSimulating] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleSimulateThreat = async () => {
    setIsSimulating(true);
    setMessage(null);

    try {
      // Call the demo endpoint to simulate a threat
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/api/threats/demo/simulate-threat`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' } }
      );

      if (!response.ok) {
        throw new Error('Failed to simulate threat');
      }

      setMessage({
        type: 'success',
        text: 'Threat simulated! Check the threat feed for the broadcasted event.',
      });
    } catch (error) {
      setMessage({
        type: 'error',
        text: error instanceof Error ? error.message : 'Failed to simulate threat',
      });
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <Card className="bg-slate-800 border-slate-700">
      <CardHeader>
        <CardTitle className="text-white">Threat Simulator</CardTitle>
        <CardDescription className="text-slate-400">
          Simulate a real-time threat detection for testing
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {message && (
          <Alert variant={message.type === 'success' ? 'default' : 'destructive'}>
            <AlertDescription>{message.text}</AlertDescription>
          </Alert>
        )}

        <p className="text-sm text-slate-300">
          This will simulate a critical rogue access point detection and broadcast it to all connected WebSocket clients in real-time.
        </p>

        <Button
          onClick={handleSimulateThreat}
          disabled={isSimulating}
          className="w-full"
          variant="default"
        >
          {isSimulating ? 'Simulating...' : 'Simulate Critical Threat'}
        </Button>

        <div className="text-xs text-slate-400 space-y-1">
          <p className="font-semibold">What happens:</p>
          <ul className="list-disc list-inside space-y-1">
            <li>Flask backend receives simulation request</li>
            <li>Threat event is generated with critical severity</li>
            <li>Event is broadcast via Socket.io to all connected clients</li>
            <li>Your threat feed updates in real-time (&lt; 500ms)</li>
            <li>Screen flashes red for visual feedback</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
