'use client'

import React, { useState, useMemo, forwardRef, useImperativeHandle } from 'react'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Hash, Lock, Unlock, ChevronUp, ChevronDown, ChevronsUpDown, Clock } from 'lucide-react'

function formatAPUptime(seconds: number | undefined) {
  if (seconds === undefined || seconds === null || isNaN(seconds) || seconds < 0) return null;
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;

  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

type SortDirection = 'asc' | 'desc'
type SortKey = 'updated_at' | 'created_at' | 'ssid' | 'source_mac' | 'vendor' | 'channel' | 'signal' | 'security' | 'clients_count' | 'severity'

interface SortConfig {
  key: SortKey
  direction: SortDirection
}

const SEVERITY_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 }

export interface ThreatTableRef {
  exportCurrentViewCSV: (customData?: any[], timeframe?: string) => void;
}

export const ThreatTable = forwardRef<ThreatTableRef, { threats: any[] }>(({ threats }, ref) => {
  const [sortConfig, setSortConfig] = useState<SortConfig>({ key: 'created_at', direction: 'desc' })

  const handleSort = (key: SortKey) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'desc' ? 'asc' : 'desc'
    }))
  }

  const SortIcon = ({ columnKey }: { columnKey: SortKey }) => {
    if (sortConfig.key !== columnKey) {
      return <ChevronsUpDown className="w-3.5 h-3.5 text-slate-600 ml-1.5 inline-block shrink-0" />
    }
    return sortConfig.direction === 'desc'
      ? <ChevronDown className="w-3.5 h-3.5 text-emerald-400 ml-1.5 inline-block shrink-0" />
      : <ChevronUp className="w-3.5 h-3.5 text-emerald-400 ml-1.5 inline-block shrink-0" />
  }

  const sortedThreats = useMemo(() => {
    const sorted = [...threats]
    const { key, direction } = sortConfig
    const multiplier = direction === 'asc' ? 1 : -1

    sorted.sort((a, b) => {
      let valA: any
      let valB: any

      switch (key) {
        case 'updated_at': {
          const dateA = a.updated_at || a.created_at || ''
          const dateB = b.updated_at || b.created_at || ''
          valA = dateA ? new Date(dateA).getTime() : 0
          valB = dateB ? new Date(dateB).getTime() : 0
          if (isNaN(valA)) valA = 0
          if (isNaN(valB)) valB = 0
          return (valA - valB) * multiplier
        }
        case 'created_at': {
          const dateA = a.created_at || ''
          const dateB = b.created_at || ''
          valA = dateA ? new Date(dateA).getTime() : 0
          valB = dateB ? new Date(dateB).getTime() : 0
          if (isNaN(valA)) valA = 0
          if (isNaN(valB)) valB = 0
          return (valA - valB) * multiplier
        }
        case 'ssid': {
          valA = (a.ssid || '').toLowerCase()
          valB = (b.ssid || '').toLowerCase()
          return valA.localeCompare(valB) * multiplier
        }
        case 'source_mac': {
          valA = (a.source_mac || '').toLowerCase()
          valB = (b.source_mac || '').toLowerCase()
          return valA.localeCompare(valB) * multiplier
        }
        case 'vendor': {
          valA = (a.vendor || 'Unknown').toLowerCase()
          valB = (b.vendor || 'Unknown').toLowerCase()
          return valA.localeCompare(valB) * multiplier
        }
        case 'channel': {
          valA = Number(a.channel) || 0
          valB = Number(b.channel) || 0
          return (valA - valB) * multiplier
        }
        case 'signal': {
          valA = Number(a.signal) || -100
          valB = Number(b.signal) || -100
          return (valA - valB) * multiplier
        }
        case 'security': {
          valA = ([a.auth, a.encryption].filter(Boolean).join(' / ') || 'Unknown').toLowerCase()
          valB = ([b.auth, b.encryption].filter(Boolean).join(' / ') || 'Unknown').toLowerCase()
          return valA.localeCompare(valB) * multiplier
        }
        case 'clients_count': {
          valA = Number(a.clients_count) || 0
          valB = Number(b.clients_count) || 0
          return (valA - valB) * multiplier
        }
        case 'severity': {
          valA = SEVERITY_RANK[(a.severity || '').toLowerCase()] || 0
          valB = SEVERITY_RANK[(b.severity || '').toLowerCase()] || 0
          return (valA - valB) * multiplier
        }
        default:
          return 0
      }
    })

    return sorted
  }, [threats, sortConfig])
useImperativeHandle(ref, () => ({
    exportCurrentViewCSV: (customData?: any[], timeframe?: string) => {
      
      const headers = [
        "First Seen", "Last Seen", "SSID", "BSSID", "Node ID", 
        "Vendor", "Channel/Band", "RSSI (dBm)", "Security", 
        "WPS Status", "Clients", "Severity"
      ];

      const formatDateLocal = (dateStr: string) => {
        if (!dateStr) return '--';
        const d = new Date(dateStr.endsWith('Z') || dateStr.includes('+') ? dateStr : dateStr + 'Z');
        const time = d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit', hour12: true});
        const date = `${d.getDate().toString().padStart(2, '0')}/${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getFullYear()}`;
        return `${time} - ${date}`;
      };

      const escapeCSV = (str: any) => {
        if (str === null || str === undefined) return '"--"';
        return `"${String(str).replace(/"/g, '""')}"`;
      };

      let dataToExport = customData ? [...customData] : [...sortedThreats];

      if (timeframe === 'monthly') {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        dataToExport = dataToExport.filter((threat: any) => {
          return new Date(threat.created_at) >= thirtyDaysAgo;
        });
      }

      if (customData) {
        dataToExport.sort((a: any, b: any) => {
          const { key, direction } = sortConfig;
          const dir = direction === 'asc' ? 1 : -1;
          
          let aVal = a[key];
          let bVal = b[key];

          if (key === 'severity') {
            const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
            aVal = rank[(aVal || '').toLowerCase()] || 0;
            bVal = rank[(bVal || '').toLowerCase()] || 0;
          }

          if (aVal === null || aVal === undefined) aVal = '';
          if (bVal === null || bVal === undefined) bVal = '';

          if (aVal < bVal) return -1 * dir;
          if (aVal > bVal) return 1 * dir;
          return 0;
        });
      }

      const rows = dataToExport.map((threat: any) => {
        const secSet = new Set(
          [threat.auth, threat.encryption]
            .map((s: string) => (s || '').toUpperCase().trim())
            .filter((s: string) => s && s !== 'UNKNOWN')
        );
        const securityValue = secSet.size > 0 ? Array.from(secSet).join(' / ') : 'UNKNOWN';

        return [
          escapeCSV(formatDateLocal(threat.created_at)),
          escapeCSV(formatDateLocal(threat.updated_at || threat.created_at)),
          escapeCSV(threat.ssid ? threat.ssid : '<Hidden Network>'),
          escapeCSV(threat.source_mac),
          escapeCSV(threat.node_id ? String(threat.node_id).padStart(2, '0') : '--'),
          escapeCSV(threat.vendor || 'Unknown'),
          escapeCSV(`${threat.channel || '--'} / ${threat.band || 'Unknown'}`),
          escapeCSV(threat.signal ? threat.signal : '--'),
          escapeCSV(securityValue),
          escapeCSV(threat.wps_status || 'DISABLED'),
          escapeCSV(threat.clients_count ?? 0),
          escapeCSV((threat.severity || 'UNKNOWN').toUpperCase())
        ].join(',');
      });

      const csvContent = '\uFEFF' + [headers.join(','), ...rows].join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `ZeinaGuard_${timeframe === 'monthly' ? 'Monthly' : (timeframe === 'all' ? 'AllTime' : 'CurrentView')}_Report.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  }));

  const getSeverityBadge = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === 'HIGH' || s === 'CRITICAL') return <Badge className="bg-red-950/30 text-red-400 border border-red-500/20 shadow-none rounded-sm text-base px-2.5 py-0.5">{s}</Badge>
    if (s === 'MEDIUM') return <Badge className="bg-amber-950/30 text-amber-400 border border-amber-500/20 shadow-none rounded-sm text-base px-2.5 py-0.5">MEDIUM</Badge>
    return <Badge className="bg-emerald-950/30 text-emerald-400 border border-emerald-500/20 shadow-none rounded-sm text-base px-2.5 py-0.5">LOW</Badge>
  }

  const parseDate = (dateStr: string) => {
    if (!dateStr) return null;
    return new Date(dateStr.endsWith('Z') || dateStr.includes('+') ? dateStr : dateStr + 'Z');
  }

  const formatDateToDDMMYYYY = (d: Date | null) => {
    if (!d) return '--';
    return `${d.getDate().toString().padStart(2, '0')}/${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getFullYear()}`;
  }

  const thBase = "font-semibold text-base tracking-wide cursor-pointer select-none transition-colors duration-150 hover:text-emerald-300 py-3.5"
  const thActive = (key: SortKey) => sortConfig.key === key ? 'text-emerald-400' : 'text-slate-300'

  return (
    <div className="rounded-xl border border-emerald-500/10 bg-slate-900/40 backdrop-blur-md overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="border-b border-emerald-500/10 hover:bg-transparent">

            <TableHead className="text-sm font-semibold text-slate-500 uppercase tracking-widest cursor-pointer select-none transition-colors duration-150 hover:text-emerald-300 py-3.5" onClick={() => handleSort('created_at')}>
              <span className="inline-flex items-center">First Seen<SortIcon columnKey="created_at" /></span>
            </TableHead>
            <TableHead className="text-sm font-semibold text-slate-500 uppercase tracking-widest cursor-pointer select-none transition-colors duration-150 hover:text-emerald-300 py-3.5" onClick={() => handleSort('updated_at')}>
              <span className="inline-flex items-center">Last Seen<SortIcon columnKey="updated_at" /></span>
            </TableHead>
            <TableHead className={`${thBase} ${thActive('ssid')}`} onClick={() => handleSort('ssid')}>
              <span className="inline-flex items-center">SSID<SortIcon columnKey="ssid" /></span>
            </TableHead>
            <TableHead className={`${thBase} ${thActive('source_mac')}`} onClick={() => handleSort('source_mac')}>
              <span className="inline-flex items-center">BSSID<SortIcon columnKey="source_mac" /></span>
            </TableHead>
            <TableHead className={`${thBase} ${thActive('vendor')}`} onClick={() => handleSort('vendor')}>
              <span className="inline-flex items-center">Vendor<SortIcon columnKey="vendor" /></span>
            </TableHead>
            <TableHead className={`${thBase} ${thActive('channel')} text-right`} onClick={() => handleSort('channel')}>
              <span className="inline-flex items-center justify-end w-full">CH / BAND<SortIcon columnKey="channel" /></span>
            </TableHead>
            <TableHead className={`${thBase} ${thActive('signal')} text-right`} onClick={() => handleSort('signal')}>
              <span className="inline-flex items-center justify-end w-full">RSSI<SortIcon columnKey="signal" /></span>
            </TableHead>
            <TableHead className={`${thBase} ${thActive('security')} pl-4`} onClick={() => handleSort('security')}>
              <span className="inline-flex items-center">Security<SortIcon columnKey="security" /></span>
            </TableHead>
            <TableHead className={`${thBase} ${thActive('clients_count')} text-right`} onClick={() => handleSort('clients_count')}>
              <span className="inline-flex items-center justify-end w-full">Clients<SortIcon columnKey="clients_count" /></span>
            </TableHead>
            <TableHead className={`${thBase} ${thActive('severity')} pl-4`} onClick={() => handleSort('severity')}>
              <span className="inline-flex items-center">Severity<SortIcon columnKey="severity" /></span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sortedThreats.map((threat) => {
            const date = parseDate(threat.updated_at || threat.created_at)
            const firstSeen = parseDate(threat.created_at)
            const secSet = new Set(
              [threat.auth, threat.encryption]
                .map(s => (s || '').toUpperCase().trim())
                .filter(s => s && s !== 'UNKNOWN')
            );
            const securityValue = secSet.size > 0 ? Array.from(secSet).join(' / ') : 'UNKNOWN';

            return (
              <TableRow
                key={threat.id}
                className="border-b border-slate-800/50 transition-colors duration-150 hover:bg-slate-800/30"
              >
                {/* FIRST SEEN */}
                <TableCell className="whitespace-nowrap py-4 align-top">
                  {firstSeen ? (
                    <div className="flex flex-col">
                      <span className="text-base font-mono text-slate-400 tabular-nums">{firstSeen.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit', hour12: true})}</span>
                      <span className="text-xs font-mono text-slate-600 mt-0.5 tabular-nums">{formatDateToDDMMYYYY(firstSeen)}</span>
                    </div>
                  ) : <span className="text-slate-600 font-mono">--</span>}
                </TableCell>

                {/* LAST SEEN */}
                <TableCell className="whitespace-nowrap py-4 align-top">
                  {date ? (
                    <div className="flex flex-col">
                      <span className="text-base font-mono text-slate-200 font-medium tabular-nums">{date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit', hour12: true})}</span>
                      <span className="text-xs font-mono text-slate-500 mt-0.5 tabular-nums">{formatDateToDDMMYYYY(date)}</span>
                    </div>
                  ) : <span className="text-slate-600 font-mono">--</span>}
                </TableCell>

                {/* SSID */}
                <TableCell className="py-4 align-top">
                  <div className="flex flex-col gap-1">
                    <span className="font-semibold text-slate-200 text-base max-w-[200px] truncate">
                      {threat.ssid || <span className="text-slate-500 font-normal italic">&lt;Hidden Network&gt;</span>}
                    </span>
                  </div>
                </TableCell>

                {/* BSSID */}
                <TableCell className="py-4 align-top tabular-nums">
                  <div className="flex flex-col items-start gap-1">
                    <div className="inline-flex items-center font-mono text-sm text-emerald-400/70 tracking-widest bg-emerald-500/5 px-2 py-0.5 rounded border border-emerald-500/10">
                      {threat.source_mac}
                    </div>
                    {threat.node_id && (
                      <span className="text-xs font-mono text-slate-500/80 bg-slate-800/50 px-1.5 py-0.5 rounded border border-slate-700/50 inline-block mt-1.5">
                        NODE: {String(threat.node_id).padStart(2, '0')}
                      </span>
                    )}
                  </div>
                </TableCell>

                {/* VENDOR & AP UPTIME */}
                <TableCell className="py-4 align-top">
                  <div className="flex flex-col items-start gap-1">
                    {threat.vendor && threat.vendor !== 'Unknown' ? (
                      <span className="text-base text-slate-400 truncate max-w-[120px]" title={threat.vendor}>{threat.vendor}</span>
                    ) : (
                      <span className="text-base text-slate-600 italic">Unknown</span>
                    )}
                    {threat.ap_uptime !== undefined && threat.ap_uptime > 0 && (
                      <span className="text-xs font-mono text-emerald-400/90 bg-emerald-950/30 px-1.5 py-0.5 rounded-sm border border-emerald-500/10 w-fit flex items-center gap-1 mt-1.5">
                        <Clock size={14} className="opacity-70" /> AP UPTIME: {formatAPUptime(threat.ap_uptime)}
                      </span>
                    )}
                  </div>
                </TableCell>

                {/* CH / BAND */}
                <TableCell className="text-right py-4 align-top tabular-nums">
                  <div className="flex flex-col items-end">
                    <span className="font-mono text-base font-medium text-slate-200">{threat.channel || <span className="text-slate-600">--</span>}</span>
                    <span className="text-xs text-slate-500 font-mono mt-1.5">{threat.band || 'Unknown'}</span>
                  </div>
                </TableCell>

                {/* RSSI */}
                <TableCell className="text-right py-4 align-top tabular-nums">
                  {threat.signal ? (
                    <span className={`font-mono text-base font-medium ${threat.signal > -60 ? 'text-emerald-500' : threat.signal >= -80 ? 'text-yellow-500' : 'text-red-500'}`}>
                      {threat.signal} dBm
                    </span>
                  ) : (
                    <span className="text-slate-600 font-mono">--</span>
                  )}
                </TableCell>

                {/* SECURITY & WPS */}
                <TableCell className="py-4 align-top pl-4">
                  <div className="flex flex-col items-start gap-1">
                    <div className="flex items-center gap-1.5 h-6">
                      {securityValue === 'OPEN' ? <Unlock className="w-4 h-4 text-red-500 shrink-0" /> : <Lock className="w-4 h-4 text-emerald-500/50 shrink-0" />}
                      <span className={`font-mono text-base font-semibold ${securityValue === 'OPEN' ? 'text-red-400' : 'text-slate-300'}`}>{securityValue}</span>
                    </div>
                    {threat.wps_status && threat.wps_status !== 'DISABLED' && (
                      <div className="flex items-center mt-1.5">
                        {threat.wps_status === 'UNLOCKED' ? (
                          <span className="text-xs font-mono text-orange-500/80 bg-orange-950/20 px-1.5 py-0.5 rounded border border-orange-500/10 flex items-center gap-1">
                            <Unlock className="w-3 h-3" /> WPS
                          </span>
                        ) : (
                          <span className="text-xs font-mono text-slate-500 flex items-center gap-1 px-1.5 py-0.5">
                            <Lock className="w-3 h-3" /> WPS
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </TableCell>

                {/* CLIENTS */}
                <TableCell className="text-right py-4 align-top tabular-nums">
                  <span className="font-mono text-base font-medium text-slate-200">
                    {threat.clients_count ?? 0}
                  </span>
                </TableCell>

                {/* SEVERITY */}
                <TableCell className="py-4 align-top pl-4">
                  <div className="h-6 flex items-center">
                    {getSeverityBadge(threat.severity)}
                  </div>
                </TableCell>

              </TableRow>
            )
          })}
          {threats.length === 0 && (
            <TableRow>
              <TableCell colSpan={10} className="h-36 text-center text-slate-500 font-mono text-base">
                No active signatures found in matrix.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  )
})