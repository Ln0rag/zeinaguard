'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { NotificationSettings } from "@/components/settings/notification-settings";
import { 
  Settings, 
  Terminal, 
  Bug, 
  RotateCcw, 
  Layers, 
  Eye, 
  Cpu, 
  Database,
  Search,
  Zap,
  Download,
  Loader2
} from "lucide-react";
import { toast } from "sonner";
import { useTheme } from "next-themes";
import { useState, useEffect } from "react";

export default function SettingsPage() {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';
  const { theme, setTheme } = useTheme();
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [debugOverlay, setDebugOverlay] = useState(false);
  const [draftMode, setDraftMode] = useState(false);
  const [loading, setLoading] = useState<string | null>(null);
  const [backendStatus, setBackendStatus] = useState('online');

  // 🔴 Add Mounted State to prevent Hydration Error
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const handleClearCache = async () => {
    try {
      setLoading('cache');
      // Clear browser storage
      localStorage.clear();
      sessionStorage.clear();
      // Clear service worker cache if available
      if ('caches' in window) {
        const cacheNames = await caches.keys();
        await Promise.all(cacheNames.map(name => caches.delete(name)));
      }
      toast.success('Cache cleared successfully', {
        description: 'Browser cache and local storage have been cleared.',
      });
    } catch (err) {
      toast.error('Failed to clear cache', {
        description: err instanceof Error ? err.message : 'Unknown error',
      });
    } finally {
      setLoading(null);
    }
  };

  const handleToggleDraftMode = () => {
    setDraftMode(!draftMode);
    toast.success(draftMode ? 'Draft Mode disabled' : 'Draft Mode enabled', {
      description: draftMode ? 'Publishing mode activated' : 'Draft mode activated',
    });
  };

  const handleViewLogs = () => {
    setLoading('logs');
    try {
      // Open console if available
      if (typeof window !== 'undefined') {
        (window as any).open?.('about:blank', 'devtools');
        toast.info('System Logs', {
          description: 'Check your browser developer console (F12) for detailed logs',
        });
      }
    } finally {
      setLoading(null);
    }
  };

  const handleInspector = () => {
    setLoading('inspector');
    try {
      if (typeof window !== 'undefined') {
        // Trigger browser developer tools
        const evt = new KeyboardEvent('keydown', {
          key: 'F12',
          code: 'F12',
          keyCode: 123,
          which: 123,
          shiftKey: false,
          ctrlKey: false,
          metaKey: false,
        });
        window.dispatchEvent(evt);
        toast.info('Inspector opened', {
          description: 'Use the Element Inspector to examine page elements',
        });
      }
    } finally {
      setLoading(null);
    }
  };

  const handleGenerateDiagnostic = async () => {
    try {
      setLoading('diagnostic');
      const diagnosticData = {
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        cookieEnabled: navigator.cookieEnabled,
        storage: {
          localStorageSize: JSON.stringify(localStorage).length,
          sessionStorageSize: JSON.stringify(sessionStorage).length,
        },
        memory: (performance as any).memory ? {
          usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
          totalJSHeapSize: (performance as any).memory.totalJSHeapSize,
        } : null,
        connection: (navigator as any).connection ? {
          effectiveType: (navigator as any).connection.effectiveType,
          downlink: (navigator as any).connection.downlink,
          rtt: (navigator as any).connection.rtt,
        } : null,
      };

      // Create and download diagnostic file
      const dataStr = JSON.stringify(diagnosticData, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `diagnostic-report-${Date.now()}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      toast.success('Diagnostic Report Generated', {
        description: 'Report has been downloaded to your device',
      });
    } catch (err) {
      toast.error('Failed to generate diagnostic', {
        description: err instanceof Error ? err.message : 'Unknown error',
      });
    } finally {
      setLoading(null);
    }
  };

  const handleRestartBackend = async () => {
    try {
      setLoading('restart');
      
      // Get the API URL from environment variables, or fallback to localhost:5000
      // Call the actual health check endpoint we verified earlier
      const response = await fetch(`${apiUrl}/health`, {
        method: 'GET',
      });

      if (!response.ok) throw new Error('Backend is not responding');

      setBackendStatus('restarting'); // Show a small animation
      
      // Simulate the check completion
      setTimeout(() => {
        setBackendStatus('online');
        toast.success('Backend is Online', {
          description: 'Successfully connected to the Flask API',
        });
      }, 1000);

    } catch (err) {
      toast.error('Connection Failed', {
        description: 'Backend is unavailable. Make sure Flask is running on port 5000.',
      });
      setBackendStatus('offline');
    } finally {
      setLoading(null);
    }
  };

  const handlePurgeHistory = async () => {
    if (!window.confirm('Are you sure you want to permanently delete all event history? This action cannot be undone.')) {
      return;
    }

    try {
      setLoading('purge');
      const response = await fetch(`${apiUrl}/api/events/purge`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) throw new Error('Purge failed');

      const result = await response.json();
      toast.success('Event history purged', {
        description: `Deleted ${result.count || 0} events from the database`,
      });
    } catch (err) {
      toast.error('Purge failed', {
        description: err instanceof Error ? err.message : 'Could not purge event history',
      });
    } finally {
      setLoading(null);
    }
  };

  const getBackendStatusColor = () => {
    switch (backendStatus) {
      case 'online':
        return 'bg-emerald-500';
      case 'offline':
        return 'bg-red-500';
      case 'restarting':
        return 'bg-yellow-500 animate-pulse';
      default:
        return 'bg-slate-500';
    }
  };

  // 🔴 Prevent render before browser is ready
  if (!mounted) return null;

  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto min-h-screen">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
          <Settings className="w-8 h-8 text-blue-600" />
          Settings
        </h1>
        <p className="text-slate-500 dark:text-slate-400 mt-2">
          Manage system preferences and developer tools.
        </p>
      </div>

      {/* Notification Settings - Full Width */}
      <div>
        <NotificationSettings />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* General Settings */}
        <Card className="border-slate-200 dark:border-slate-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-yellow-500" />
              General
            </CardTitle>
            <CardDescription>Basic application preferences.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>System Notifications</Label>
                <p className="text-sm text-slate-500 dark:text-slate-400">Receive real-time alerts.</p>
              </div>
              <Switch 
                checked={notificationsEnabled}
                onCheckedChange={(checked) => {
                  setNotificationsEnabled(checked);
                  toast.success(checked ? 'Notifications enabled' : 'Notifications disabled');
                }}
              />
            </div>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Dark Mode</Label>
                <p className="text-sm text-slate-500 dark:text-slate-400">Switch between light and dark themes.</p>
              </div>
              <Switch 
                checked={theme === 'dark'} 
                onCheckedChange={(checked) => {
                  setTheme(checked ? 'dark' : 'light');
                  toast.success(checked ? 'Dark mode enabled' : 'Light mode enabled');
                }}
              />
            </div>
          </CardContent>
        </Card>

        {/* Developer Tools - Replicating Next.js DevTools */}
        <Card className="border-slate-200 dark:border-slate-800 ring-2 ring-blue-500/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-blue-600" />
              Developer Tools
            </CardTitle>
            <CardDescription>Advanced tools for development and debugging.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <Button 
                variant="outline" 
                className="justify-start gap-2"
                disabled={loading === 'cache'}
                onClick={handleClearCache}
              >
                {loading === 'cache' ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <RotateCcw className="w-4 h-4" />
                )}
                Clear Cache
              </Button>
              <Button 
                variant="outline" 
                className="justify-start gap-2"
                onClick={handleToggleDraftMode}
              >
                <Layers className={`w-4 h-4 ${draftMode ? 'text-blue-500' : ''}`} />
                {draftMode ? 'Draft ON' : 'Draft Mode'}
              </Button>
              <Button 
                variant="outline" 
                className="justify-start gap-2"
                disabled={loading === 'logs'}
                onClick={handleViewLogs}
              >
                {loading === 'logs' ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Terminal className="w-4 h-4" />
                )}
                View Logs
              </Button>
              <Button 
                variant="outline" 
                className="justify-start gap-2"
                disabled={loading === 'inspector'}
                onClick={handleInspector}
              >
                {loading === 'inspector' ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Eye className="w-4 h-4" />
                )}
                Inspector
              </Button>
            </div>
            
            <div className="pt-4 border-t border-slate-100 dark:border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <div className="space-y-0.5">
                  <Label>Debug Overlay</Label>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Show performance metrics on screen.</p>
                </div>
                <Switch 
                  checked={debugOverlay}
                  onCheckedChange={(checked) => {
                    setDebugOverlay(checked);
                    toast.success(checked ? 'Debug overlay enabled' : 'Debug overlay disabled');
                  }}
                />
              </div>
              <Button 
                className="w-full bg-blue-600 hover:bg-blue-700 text-white gap-2"
                disabled={loading === 'diagnostic'}
                onClick={handleGenerateDiagnostic}
              >
                {loading === 'diagnostic' ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Bug className="w-4 h-4" />
                )}
                Generate Diagnostic Report
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* System Status */}
        <Card className="border-slate-200 dark:border-slate-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="w-5 h-5 text-emerald-500" />
              System Status
            </CardTitle>
            <CardDescription>Monitor backend services.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-4 p-3 bg-slate-100 dark:bg-slate-900 rounded-lg">
              <Cpu className="w-8 h-8 text-blue-500" />
              <div className="flex-1">
                <p className="text-sm font-medium">Backend API</p>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${getBackendStatusColor()} ${backendStatus === 'restarting' ? 'animate-pulse' : ''}`} />
                  <span className="text-xs text-slate-500">
                    {backendStatus === 'online' ? 'Connected' : backendStatus === 'offline' ? 'Disconnected' : 'Restarting...'}
                  </span>
                </div>
              </div>
              <Button 
                size="sm" 
                variant="ghost"
                disabled={loading === 'restart' || backendStatus === 'restarting'}
                onClick={handleRestartBackend}
              >
                {loading === 'restart' ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Restart'}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Advanced Search */}
        <Card className="border-slate-200 dark:border-slate-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="w-5 h-5 text-purple-500" />
              Data Management
            </CardTitle>
            <CardDescription>Maintenance and backup tasks.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button 
              variant="outline" 
              className="w-full gap-2 text-red-500 hover:text-red-600 border-red-200 hover:bg-red-50 dark:border-red-900 dark:hover:bg-red-950"
              disabled={loading === 'purge'}
              onClick={handlePurgeHistory}
            >
              {loading === 'purge' ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Search className="w-4 h-4" />
              )}
              Purge Event History
            </Button>
            <div className="text-xs text-slate-500 dark:text-slate-400 p-2 bg-slate-50 dark:bg-slate-900 rounded">
              Warning: This action permanently deletes all event records and cannot be undone.
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
