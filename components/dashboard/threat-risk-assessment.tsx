'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertTriangle, AlertCircle, TrendingUp } from 'lucide-react';
interface ThreatRisk {
  threat_type: string;
  count: number;
  avg_risk_score: number;
  detection_rate: number;
  mitigation_status: string;
}

export function ThreatRiskAssessment() {
  const [threats, setThreats] = useState<ThreatRisk[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [overallRiskScore, setOverallRiskScore] = useState(0);

  useEffect(() => {
    const fetchThreatRisks = async () => {
      try {
        setLoading(true);
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/api/dashboard/threat-assessment`,
          { headers: { 'Content-Type': 'application/json' } }
        );

        if (!response.ok) throw new Error('Failed to fetch threat risks');
        const data = await response.json();
        setThreats(Array.isArray(data.threats) ? data.threats : []);
        setOverallRiskScore(data.overall_risk_score || 0);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load threat risks');
      } finally {
        setLoading(false);
      }
    };

    fetchThreatRisks();
    const interval = setInterval(fetchThreatRisks, 20000);
    return () => clearInterval(interval);
  }, []);

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-400';
    if (score >= 60) return 'text-orange-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getRiskBgColor = (score: number) => {
    if (score >= 80) return 'bg-red-900/20 border-red-700';
    if (score >= 60) return 'bg-orange-900/20 border-orange-700';
    if (score >= 40) return 'bg-yellow-900/20 border-yellow-700';
    return 'bg-green-900/20 border-green-700';
  };

  if (error) {
    return (
      <Card className="border-destructive/50 bg-destructive/5">
        <CardHeader>
          <CardTitle className="text-destructive flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Risk Assessment Error
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
          <AlertTriangle className="w-5 h-5 text-orange-500" />
          Threat Risk Assessment
        </CardTitle>
        <CardDescription>AI-driven threat scoring by type</CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
          </div>
        ) : threats.length > 0 ? (
          <div className="space-y-3">
            {threats.map((threat, idx) => {
              const getColors = (score: number) => {
                if (score >= 80) return { text: 'text-red-600', bg: 'bg-red-50', border: 'border-red-200' };
                if (score >= 60) return { text: 'text-orange-600', bg: 'bg-orange-50', border: 'border-orange-200' };
                if (score >= 40) return { text: 'text-yellow-600', bg: 'bg-yellow-50', border: 'border-yellow-200' };
                return { text: 'text-green-600', bg: 'bg-green-50', border: 'border-green-200' };
              };
              const colors = getColors(threat.avg_risk_score);
              return (
                <div
                  key={idx}
                  className={`p-3 rounded-lg border ${colors.bg} ${colors.border}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1">
                      <h4 className={`font-semibold text-sm ${colors.text}`}>
                        {threat.threat_type}
                      </h4>
                      <div className="grid grid-cols-2 gap-2 mt-2 text-xs">
                        <div>
                          <span className="text-foreground/60">Detection: </span>
                          <span className={colors.text}>{threat.detection_rate.toFixed(0)}%</span>
                        </div>
                        <div>
                          <span className="text-foreground/60">Count: </span>
                          <span className={colors.text}>{threat.count}</span>
                        </div>
                      </div>
                      <div className="mt-2 text-xs">
                        <span className="text-foreground/60">Status: </span>
                        <span className={`font-medium ${colors.text}`}>
                          {threat.mitigation_status}
                        </span>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-2xl font-bold ${colors.text}`}>
                        {threat.avg_risk_score.toFixed(0)}
                      </div>
                      <span className="text-xs text-foreground/60">Risk</span>
                    </div>
                  </div>
                  <div className="mt-2 w-full bg-foreground/10 rounded-full h-1 overflow-hidden">
                    <div
                      className={`h-full ${
                        threat.avg_risk_score >= 80 ? 'bg-red-500' :
                        threat.avg_risk_score >= 60 ? 'bg-orange-500' :
                        threat.avg_risk_score >= 40 ? 'bg-yellow-500' :
                        'bg-green-500'
                      }`}
                      style={{ width: `${threat.avg_risk_score}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-8 text-foreground/60">
            <TrendingUp className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No threat data available</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
