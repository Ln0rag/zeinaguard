'use client';

import { useEffect, useState, useCallback } from 'react';
import { alertsAPI } from '@/lib/api';
import { Bell, AlertTriangle, AlertCircle, CheckCircle, Plus } from 'lucide-react';

interface Alert {
  id: number;
  rule_name: string;
  trigger_condition: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  is_active: boolean;
  created_at: string;
}

function normalizeAlert(raw: Record<string, unknown>): Alert {
  return {
    id: Number(raw.id) ?? 0,
    rule_name: String(raw.rule_name ?? raw.message ?? 'Alert'),
    trigger_condition: String(raw.trigger_condition ?? ''),
    severity: (raw.severity as Alert['severity']) ?? 'medium',
    is_active: Boolean(raw.is_active ?? (raw.is_acknowledged !== true)),
    created_at: String(raw.created_at ?? new Date().toISOString()),
  };
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showNewRule, setShowNewRule] = useState(false);

  const fetchAlerts = useCallback(async () => {
    try {
      setError(null);
      setLoading(true);
      const data = await alertsAPI.getAlerts();
      const list = Array.isArray(data) ? data : [];
      setAlerts(list.map((item: unknown) => normalizeAlert(item as Record<string, unknown>)));
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch alerts';
      setError(msg);
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
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
    switch (severity) {
      case 'critical':
        return <AlertTriangle className="w-4 h-4" />;
      case 'high':
        return <AlertCircle className="w-4 h-4" />;
      default:
        return <Bell className="w-4 h-4" />;
    }
  };

  if (loading && alerts.length === 0) {
    return (
      <div className="min-h-screen bg-slate-900 p-8 flex items-center justify-center">
        <div className="text-slate-300">Loading alerts...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-slate-900 p-8 flex items-center justify-center">
        <div className="text-center max-w-md">
          <Bell className="w-16 h-16 text-amber-500/50 mx-auto mb-4" />
          <p className="text-slate-300 font-medium mb-2">Unable to load alerts</p>
          <p className="text-slate-500 text-sm mb-4">{error}</p>
          <button
            onClick={() => fetchAlerts()}
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
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-4xl font-bold text-white flex items-center gap-3">
              <Bell className="w-10 h-10 text-blue-500" />
              Alert Rules
            </h1>
            <p className="text-slate-400 mt-2">
              Create and manage threat detection rules
            </p>
          </div>
          <button
            onClick={() => setShowNewRule(!showNewRule)}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Rule
          </button>
        </div>

        {/* New Rule Form */}
        {showNewRule && (
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4">Create Alert Rule</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-300 mb-2">Rule Name</label>
                <input
                  type="text"
                  placeholder="e.g., Block Rogue APs"
                  className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-300 mb-2">Trigger Condition</label>
                <input
                  type="text"
                  placeholder="e.g., threat_type == 'rogue_ap'"
                  className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-300 mb-2">Severity</label>
                <select className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white focus:outline-none focus:border-blue-500">
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
              </div>
              <div className="flex gap-3">
                <button className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded transition-colors">
                  Create Rule
                </button>
                <button
                  onClick={() => setShowNewRule(false)}
                  className="flex-1 bg-slate-700 hover:bg-slate-600 text-slate-300 px-4 py-2 rounded transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Alerts List */}
        <div className="space-y-4">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              className={`border rounded-lg p-6 flex items-start justify-between ${getSeverityColor(
                alert.severity
              )}`}
            >
              <div className="flex items-start gap-4 flex-1">
                {getSeverityIcon(alert.severity)}
                <div className="flex-1">
                  <h3 className="font-semibold text-lg">{alert.rule_name}</h3>
                  <p className="text-sm opacity-90 mt-1">{alert.trigger_condition}</p>
                  <p className="text-xs opacity-75 mt-2">
                    Created: {new Date(alert.created_at).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs px-3 py-1 rounded-full bg-black/20">
                  {alert.severity.toUpperCase()}
                </span>
                {alert.is_active ? (
                  <CheckCircle className="w-5 h-5" />
                ) : (
                  <AlertCircle className="w-5 h-5 opacity-50" />
                )}
              </div>
            </div>
          ))}
        </div>

        {alerts.length === 0 && !loading && (
          <div className="text-center py-12">
            <Bell className="w-16 h-16 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400 text-lg">No alert rules configured</p>
          </div>
        )}
      </div>
    </div>
  );
}
