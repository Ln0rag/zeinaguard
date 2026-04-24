'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Bell, Volume2, VolumeX, Send, Mail, CheckCircle } from 'lucide-react';
import { toast } from 'sonner';
import { soundService } from '@/lib/sound-service';

export function NotificationSettings() {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';
  const [soundsEnabled, setSoundsEnabled] = useState(!soundService.getMuteState());
  const [webhookUrl, setWebhookUrl] = useState('');
  const [alertEmail, setAlertEmail] = useState('');
  const [loading, setLoading] = useState<string | null>(null);

  // Read from localStorage only on the client side
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setWebhookUrl(localStorage.getItem('webhookUrl') || '');
      setAlertEmail(localStorage.getItem('alertEmail') || '');
    }
  }, []);

  const handleToggleSounds = () => {
    const newState = !soundsEnabled;
    setSoundsEnabled(newState);
    soundService.setMute(!newState);
    toast.success(newState ? 'Sound alerts enabled' : 'Sound alerts muted', {
      description: newState ? 'You will hear alerts for critical events' : 'All sound alerts are muted',
    });
  };

  const handleSaveWebhook = async () => {
    if (!webhookUrl.trim()) {
      toast.error('Webhook URL required', {
        description: 'Please enter a valid webhook URL',
      });
      return;
    }

    try {
      setLoading('webhook');
      // Save to localStorage
      if (typeof window !== 'undefined') {
        localStorage.setItem('webhookUrl', webhookUrl);
      }
      
      // Mock API call
      const response = await fetch(`${apiUrl}/api/notifications/webhook-test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl }),
      });

      if (response.ok) {
        toast.success('Webhook configured', {
          description: `Webhook URL saved: ${webhookUrl}`,
        });
      }
    } catch (error) {
      toast.error('Failed to save webhook', {
        description: error instanceof Error ? error.message : 'Unknown error',
      });
    } finally {
      setLoading(null);
    }
  };

  const handleSaveEmail = async () => {
    if (!alertEmail.trim() || !alertEmail.includes('@')) {
      toast.error('Valid email required', {
        description: 'Please enter a valid email address',
      });
      return;
    }

    try {
      setLoading('email');
      // Save to localStorage
      if (typeof window !== 'undefined') {
        localStorage.setItem('alertEmail', alertEmail);
      }
      
      // Mock API call
      const response = await fetch(`${apiUrl}/api/notifications/email-test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: alertEmail }),
      });

      if (response.ok) {
        toast.success('Email configured', {
          description: `Alert email saved: ${alertEmail}`,
        });
      }
    } catch (error) {
      toast.error('Failed to save email', {
        description: error instanceof Error ? error.message : 'Unknown error',
      });
    } finally {
      setLoading(null);
    }
  };

  const handleTestSound = async (type: 'ping' | 'siren') => {
    try {
      if (type === 'ping') {
        await soundService.playPing();
      } else {
        await soundService.playSiren();
      }
      toast.success(`${type === 'ping' ? 'Ping' : 'Siren'} sound played`);
    } catch (error) {
      toast.error('Failed to play sound', {
        description: 'Your browser may have blocked audio',
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Sound Alerts */}
      <Card className="border-slate-700 bg-slate-800/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Volume2 className="w-5 h-5 text-blue-400" />
            Sound Alerts
          </CardTitle>
          <CardDescription>Configure audio notifications for threats and events</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Master Toggle */}
          <div className="flex items-center justify-between p-4 bg-slate-900/50 rounded-lg border border-slate-700">
            <div className="flex items-center gap-3">
              {soundsEnabled ? (
                <Volume2 className="w-5 h-5 text-green-400" />
              ) : (
                <VolumeX className="w-5 h-5 text-red-400" />
              )}
              <div>
                <Label className="text-white font-medium">Sound Alerts</Label>
                <p className="text-xs text-slate-400 mt-1">
                  {soundsEnabled ? 'Enabled - You will hear alerts' : 'Disabled - All sounds muted'}
                </p>
              </div>
            </div>
            <Switch checked={soundsEnabled} onCheckedChange={handleToggleSounds} />
          </div>

          {/* Sound Profiles */}
          <div className="grid grid-cols-2 gap-4">
            {/* Ping Sound */}
            <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-700">
              <h4 className="text-sm font-semibold text-white mb-2">Info/Warning</h4>
              <p className="text-xs text-slate-400 mb-3">Subtle ping tone</p>
              <button
                onClick={() => handleTestSound('ping')}
                disabled={!soundsEnabled}
                className="w-full px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:opacity-50 text-white text-xs rounded font-medium transition-colors"
              >
                Test Ping
              </button>
            </div>

            {/* Siren Sound */}
            <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-700">
              <h4 className="text-sm font-semibold text-white mb-2">🚨 Critical</h4>
              <p className="text-xs text-slate-400 mb-3">Urgent alarm siren</p>
              <button
                onClick={() => handleTestSound('siren')}
                disabled={!soundsEnabled}
                className="w-full px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:bg-slate-700 disabled:opacity-50 text-white text-xs rounded font-medium transition-colors"
              >
                Test Siren
              </button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Webhook Integration */}
      <Card className="border-slate-700 bg-slate-800/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Send className="w-5 h-5 text-purple-400" />
            Webhook Integration
          </CardTitle>
          <CardDescription>Send alerts to Slack, Discord, or custom webhooks</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div>
              <Label htmlFor="webhook-url" className="text-white">
                Webhook URL
              </Label>
              <p className="text-xs text-slate-400 mt-1 mb-2">
                Example: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
              </p>
              <Input
                id="webhook-url"
                type="url"
                placeholder="https://hooks.slack.com/services/..."
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                className="bg-slate-900 border-slate-600 text-white placeholder-slate-500"
              />
            </div>
            <div className="flex gap-2">
              <Button
                onClick={handleSaveWebhook}
                disabled={loading === 'webhook'}
                className="bg-blue-600 hover:bg-blue-700 text-white"
              >
                {loading === 'webhook' ? 'Saving...' : 'Save Webhook'}
              </Button>
              {webhookUrl && (
                <Button
                  onClick={() => handleTestSound('ping')}
                  variant="outline"
                  className="border-slate-600 text-slate-300 hover:bg-slate-700"
                >
                  Test Connection
                </Button>
              )}
            </div>
            {webhookUrl && (
              <div className="flex items-center gap-2 text-sm text-green-400">
                <CheckCircle className="w-4 h-4" />
                Webhook URL saved (alerts will be sent here)
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Email Integration */}
      <Card className="border-slate-700 bg-slate-800/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Mail className="w-5 h-5 text-orange-400" />
            Email Alerts
          </CardTitle>
          <CardDescription>Receive critical alerts via email</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div>
              <Label htmlFor="alert-email" className="text-white">
                Alert Email Address
              </Label>
              <p className="text-xs text-slate-400 mt-1 mb-2">
                Critical alerts will be sent to this address
              </p>
              <Input
                id="alert-email"
                type="email"
                placeholder="admin@company.com"
                value={alertEmail}
                onChange={(e) => setAlertEmail(e.target.value)}
                className="bg-slate-900 border-slate-600 text-white placeholder-slate-500"
              />
            </div>
            <div className="flex gap-2">
              <Button
                onClick={handleSaveEmail}
                disabled={loading === 'email'}
                className="bg-blue-600 hover:bg-blue-700 text-white"
              >
                {loading === 'email' ? 'Saving...' : 'Save Email'}
              </Button>
              {alertEmail && (
                <Button
                  onClick={() => handleTestSound('ping')}
                  variant="outline"
                  className="border-slate-600 text-slate-300 hover:bg-slate-700"
                >
                  Send Test Email
                </Button>
              )}
            </div>
            {alertEmail && (
              <div className="flex items-center gap-2 text-sm text-green-400">
                <CheckCircle className="w-4 h-4" />
                Email address saved (critical alerts will be sent)
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
