'use client'

import React, { useEffect, useState, useMemo, useRef } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuCheckboxItem,
  DropdownMenuLabel,
  DropdownMenuItem, 
  DropdownMenuSeparator,
  DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Download, ShieldAlert, Activity, Search, Filter, Trash2, AlertTriangle, FileText, ChevronLeft, ChevronRight } from 'lucide-react'
import { toast } from 'sonner'
import { ThreatTable, ThreatTableRef } from '@/components/operation-center/ThreatTable'
import { useSocket } from '@/hooks/use-socket'
import { apiRequest } from '@/lib/api'
import { useAlertStore } from '@/hooks/use-alert-store'

export interface ThreatType {
  id: number;
  threat_type: string;
  severity: string;
  source_mac: string;
  ssid: string;
  action_status: string;
  is_auto_mitigated: boolean;
  created_at: string;
  updated_at?: string;
  channel?: number;
  signal?: number;
  encryption?: string;
  risk_score?: number;
  detected_by?: string | number;
  mitigated_by_sensor_id?: string;
  vendor?: string;
  
  node_id?: string | number;
  band?: string;
  wps_status?: string;
  ap_uptime?: number;
  packet_count?: number;
  tags?: string[];

  clients_count?: number;
  is_active?: boolean;
  first_seen?: string;
}

const PAGE_SIZE = 50;

const SEVERITY_OPTIONS = [
  { value: 'CRITICAL', label: 'Critical', className: 'text-red-300 font-bold' },
  { value: 'HIGH', label: 'High', className: 'text-red-400 font-semibold' },
  { value: 'MEDIUM', label: 'Medium', className: 'text-yellow-400 font-semibold' },
] as const;

export default function OperationCenterPage() {
  const [threats, setThreats] = useState<ThreatType[]>([])
  const [totalThreats, setTotalThreats] = useState(0)
  const [currentPage, setCurrentPage] = useState(1)

  const [loading, setLoading] = useState(true)
  const { isConnected, socket } = useSocket()

  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilters, setSeverityFilters] = useState<string[]>(['CRITICAL', 'HIGH', 'MEDIUM'])
  const [error, setError] = useState<string | null>(null)

  const [purgeDialogOpen, setPurgeDialogOpen] = useState(false)
  const [purgeType, setPurgeType] = useState('today')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [lastPurgeReport, setLastPurgeReport] = useState<{name: string, url: string} | null>(null)
  const [isPurging, setIsPurging] = useState(false)

  const { addNotification } = useAlertStore()

  const fetchThreats = React.useCallback(async (page = currentPage) => {
    try {
      setError(null)
      const queryParams = new URLSearchParams({
        page: String(page),
        limit: String(PAGE_SIZE),
        search: searchQuery,
        severity: severityFilters.length === 0 ? 'ALL' : severityFilters.join(',')
      });

      const { data, error: apiError } = await apiRequest<{threats: ThreatType[], total: number}>(`/api/operation-center/threats?${queryParams.toString()}`)
      
      if (apiError) throw new Error(apiError)
      if (data) {
        setThreats(data.threats || []);
        setTotalThreats(data.total ?? 0);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load threats")
    } finally {
      setLoading(false)
    }
  }, [searchQuery, severityFilters, currentPage])

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchThreats()
    }, 300)
    return () => clearTimeout(timer)
  }, [fetchThreats])

  const fetchThreatsRef = useRef(fetchThreats);
  useEffect(() => {
    fetchThreatsRef.current = fetchThreats;
  }, [fetchThreats]);

  useEffect(() => {
    if (!socket) return

    const handleReconnect = () => fetchThreatsRef.current();

    const handleThreatEvent = (payload: any) => {
      if ((payload.type === 'threat_detected' || payload.type === 'new_threat') && payload.data) {
        setThreats(prev => {
          const existingIndex = prev.findIndex(
            t => t.source_mac === payload.data.source_mac &&
                 t.threat_type === payload.data.threat_type
          );
          if (existingIndex >= 0) {
            const updated = [...prev];
            updated[existingIndex] = {
              ...updated[existingIndex], 
              ...payload.data,
              created_at: updated[existingIndex].created_at,
              first_seen: updated[existingIndex].first_seen
            };
            const [item] = updated.splice(existingIndex, 1);
            return [item, ...updated].slice(0, PAGE_SIZE);
          }
          
          return [{...payload.data}, ...prev].slice(0, PAGE_SIZE);
        });
      } else {
        fetchThreatsRef.current()
      }
    }

    const handleStatusUpdate = (payload: any) => {
      if (payload && payload.status === 'OFF' && payload.bssid) {
        setThreats(prev => {
          let changed = false;
          const updated = prev.map(t => {
            if (t.source_mac === payload.bssid && t.is_active !== false) {
              changed = true;
              return { ...t, is_active: false };
            }
            return t;
          });
          return changed ? updated : prev;
        });
      }
    };

    const handleStatsUpdate = () => fetchThreatsRef.current();

    socket.emit('join_dashboard', (ack: any) => {
      if (ack && ack.error) {
        console.warn('[OperationCenter] join_dashboard rejected:', ack.error);
      }
    });

    socket.on('connect', handleReconnect)
    socket.on('threat_event', handleThreatEvent)
    socket.on('threat_detected', handleThreatEvent)
    socket.on('status_update', handleStatusUpdate)
    socket.on('stats_update_required', handleStatsUpdate)
    
    return () => {
      socket.emit('leave_dashboard')
      socket.off('connect', handleReconnect)
      socket.off('threat_event', handleThreatEvent)
      socket.off('threat_detected', handleThreatEvent)
      socket.off('status_update', handleStatusUpdate)
      socket.off('stats_update_required', handleStatsUpdate)
    }
  }, [socket])

  const [isExporting, setIsExporting] = useState(false)
  const tableRef = useRef<ThreatTableRef>(null)

const handleExport = async (timeframe: string) => {
    try {
      setIsExporting(true);
      const toastId = toast.loading(`Fetching full dataset for ${timeframe} report...`);
      
      const response = await fetch(`/api/operation-center/threats?page=1&limit=10000&search=${encodeURIComponent(searchQuery)}&severity=${encodeURIComponent(severityFilters.length === 0 ? 'ALL' : severityFilters.join(','))}`);
      
      if (!response.ok) throw new Error('Failed to fetch full dataset for export');
      
      const result = await response.json();
      const fullDataset = result.threats || [];

      if (tableRef.current) {
        tableRef.current.exportCurrentViewCSV(fullDataset, timeframe);
        toast.success('Report downloaded successfully', { id: toastId });
      } else {
        throw new Error('Table reference not found');
      }
    } catch (err: any) {
      toast.error(err.message || 'Export error');
    } finally {
      setIsExporting(false);
    }
  }

  const handlePurge = async () => {
    try {
      setIsPurging(true)
      let payload: any = { type: purgeType }
      if (purgeType === 'range') {
        if (!startDate || !endDate) {
          toast.error("Please select both start and end dates.")
          setIsPurging(false)
          return
        }
        payload.start_date = new Date(startDate).toISOString()
        payload.end_date = new Date(endDate).toISOString()
      }

      const response = await fetch('/api/operation-center/purge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || "Failed to purge database")
      }

      try { new Audio('/system-notification.mp3').play().catch(() => {}) } catch (e) {}

      const purgeLabel = purgeType === 'today' ? "Today's Records" : purgeType === 'weekly' ? 'Last 7 Days' : purgeType === 'monthly' ? 'Last 30 Days' : purgeType === 'all' ? 'All Records' : 'Custom Range'
      if (data.count > 0) {
        const downloadUrl: string = data.download_url || ''
        toast.success(`DATABASE PURGED — ${data.count} records`, {
          description: `Scope: ${purgeLabel}. Backup report generated.`,
          duration: 8000,
          action: {
            label: 'Download Report',
            onClick: () => window.open(downloadUrl, '_blank'),
          },
        })
        setLastPurgeReport({ name: data.report_name, url: downloadUrl })
        
        addNotification({
          type: 'purge',
          title: 'DATABASE PURGED',
          bssid: 'SYSTEM',
          ssid: 'Operation Center',
          purge_count: data.count,
          purge_type: purgeType,
          report_name: data.report_name,
          download_url: downloadUrl,
        })
      } else {
        toast.info('No records found to purge.', { description: `Scope: ${purgeLabel}` })
      }
      setPurgeDialogOpen(false)
      fetchThreats()
    } catch (err: any) {
      toast.error(err.message || "An error occurred during purge.")
    } finally {
      setIsPurging(false)
    }
  }

  const totalPages = Math.max(1, Math.ceil(totalThreats / PAGE_SIZE))

  const handlePageChange = (next: number) => {
    if (next < 1 || next > totalPages) return;
    setCurrentPage(next);
    fetchThreats(next);
  }

  return (
    <div className="flex-1 space-y-8 p-6 md:px-10 md:pt-4 md:pb-10 min-h-screen bg-slate-900 text-white font-sans selection:bg-emerald-500/30">
      
      {/* Header Section */}
      <div className="flex items-center justify-between gap-4 border-b border-emerald-500/10 pb-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${isConnected ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)] animate-pulse'}`} />
          <h2 className="text-emerald-400 drop-shadow-[0_0_10px_rgba(52,211,153,0.7)] text-xl font-bold tracking-tight whitespace-nowrap">Operation Center</h2>
        </div>
        
        <div className="flex flex-wrap items-center gap-3">
          {lastPurgeReport && (
            <Button 
              className="bg-emerald-950/30 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10 hover:border-emerald-500/50 hover:text-emerald-300 transition-all shadow-sm"
              onClick={() => {
                window.open(lastPurgeReport.url, '_blank')
              }}
            >
              <FileText className="mr-2 h-4 w-4" />
              Last Purge Report
            </Button>
          )}

          <Dialog open={purgeDialogOpen} onOpenChange={setPurgeDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="destructive" className="bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all shadow-sm">
                <Trash2 className="mr-2 h-4 w-4" />
                Cleanup Database
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-slate-900 border-red-500/20 text-white sm:max-w-[425px]">
              <DialogHeader>
                <div className="flex items-center gap-2 text-red-400 mb-2">
                  <AlertTriangle className="h-6 w-6" />
                  <DialogTitle className="text-xl">Purge Database</DialogTitle>
                </div>
                <DialogDescription className="text-slate-400">
                  This action will permanently delete threat records. A backup report (CSV) will be generated before deletion.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="space-y-2">
                  <label className="text-sm text-slate-300">Timeframe</label>
                  <Select value={purgeType} onValueChange={setPurgeType}>
                    <SelectTrigger className="bg-slate-800 border-slate-700 text-white">
                      <SelectValue placeholder="Select timeframe" />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-800 border-slate-700 text-white">
                      <SelectItem value="today">Today</SelectItem>
                      <SelectItem value="weekly">Last 7 Days</SelectItem>
                      <SelectItem value="monthly">Last 30 Days</SelectItem>
                      <SelectItem value="range">Custom Date Range</SelectItem>
                      <SelectItem value="all" className="text-red-400 font-bold focus:text-red-400">Wipe Entire Database</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {purgeType === 'range' && (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label className="text-sm text-slate-300">Start Date</label>
                      <Input 
                        type="date" 
                        value={startDate} 
                        onChange={(e) => setStartDate(e.target.value)}
                        className="bg-slate-800 border-slate-700 text-white"
                        style={{ colorScheme: 'dark' }}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm text-slate-300">End Date</label>
                      <Input 
                        type="date" 
                        value={endDate} 
                        onChange={(e) => setEndDate(e.target.value)}
                        className="bg-slate-800 border-slate-700 text-white"
                        style={{ colorScheme: 'dark' }}
                      />
                    </div>
                  </div>
                )}
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setPurgeDialogOpen(false)} className="bg-transparent border-slate-700 text-white hover:bg-slate-800">
                  Cancel
                </Button>
                <Button variant="destructive" onClick={handlePurge} disabled={isPurging} className="bg-red-500 hover:bg-red-600 text-white">
                  {isPurging ? "Processing..." : "Generate Report & Confirm"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button disabled={isExporting} className="bg-emerald-950/30 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10 hover:border-emerald-500/50 transition-all shadow-sm">
                {isExporting ? <Activity className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />}
                {isExporting ? "Exporting..." : "Export Reports"}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-slate-900 border-emerald-500/20 text-emerald-100 shadow-2xl">
              <DropdownMenuItem onClick={() => handleExport('monthly')} className="focus:bg-emerald-500/10 cursor-pointer">
                Monthly Report (CSV)
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('all')} className="focus:bg-emerald-500/10 cursor-pointer">
                All-Time Report (CSV)
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>


      {/* Live Threat Matrix Section */}
      <div className="space-y-4">
        {/* Sleek Command Strip Filter Bar */}
        <div className="flex flex-col md:flex-row items-center gap-3 w-full bg-slate-900/60 p-2 rounded-lg border border-emerald-500/10 backdrop-blur-xl">
           <div className="w-full flex-1 relative">
             <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-emerald-500/40" />
             <Input 
               placeholder="Search BSSID or SSID..." 
               value={searchQuery}
               onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
               className="pl-9 bg-transparent border-none text-emerald-50 focus-visible:ring-0 placeholder:text-emerald-500/30 font-mono text-sm h-10"
             />
           </div>
           
           <div className="hidden md:block w-px h-6 bg-emerald-500/10 mx-2 shrink-0"></div>
           
           {/* Multi-select severity filter*/}
           <div className="w-full md:w-auto shrink-0 flex items-center">
             <DropdownMenu>
               <DropdownMenuTrigger asChild>
                 <Button variant="ghost" className="w-full md:w-52 bg-transparent border-none text-emerald-100 focus:ring-0 h-10 shadow-none hover:bg-slate-800/50 flex items-center gap-2 justify-start px-3 font-normal">
                   <Filter className="h-3.5 w-3.5 text-emerald-500/50 shrink-0" />
                   <span className="text-sm truncate text-emerald-100">
                     {severityFilters.length === 0 || severityFilters.length === SEVERITY_OPTIONS.length
                       ? 'All Severities'
                       : severityFilters.map(s => s.charAt(0) + s.slice(1).toLowerCase()).join(', ')}
                   </span>
                 </Button>
               </DropdownMenuTrigger>
               <DropdownMenuContent align="end" className="bg-slate-900 border-emerald-500/20 text-emerald-100 shadow-2xl min-w-[180px]">
                 <DropdownMenuLabel className="text-xs text-slate-500 uppercase tracking-widest px-2 py-1.5">Filter by Severity</DropdownMenuLabel>
                 <DropdownMenuSeparator className="bg-emerald-500/10" />
                 {SEVERITY_OPTIONS.map(opt => (
                   <DropdownMenuCheckboxItem
                     key={opt.value}
                     className={`cursor-pointer focus:bg-emerald-500/10 ${opt.className}`}
                     checked={severityFilters.includes(opt.value)}
                     onCheckedChange={(checked) => {
                       setSeverityFilters(prev => {
                         const next = checked
                           ? [...prev, opt.value]
                           : prev.filter(s => s !== opt.value);
                         setCurrentPage(1);
                         return next;
                       });
                     }}
                   >
                     {opt.label}
                   </DropdownMenuCheckboxItem>
                 ))}
               </DropdownMenuContent>
             </DropdownMenu>
           </div>
        </div>

        {loading ? (
          <div className="flex justify-center items-center h-64 rounded-lg border border-emerald-500/5 bg-slate-900/20">
            <div className="text-emerald-500/50 flex flex-col items-center gap-3">
              <Activity className="h-6 w-6 animate-spin text-emerald-400" />
              <span className="font-mono text-sm tracking-widest uppercase">Initializing Matrix...</span>
            </div>
          </div>
        ) : error ? (
          <div className="flex justify-center items-center h-64 rounded-lg border border-red-500/20 bg-red-950/10">
            <div className="text-red-400 flex flex-col items-center gap-2">
              <ShieldAlert className="h-8 w-8" />
              <span className="font-mono text-sm">{error}</span>
            </div>
          </div>
        ) : (
          <div className="animate-in fade-in duration-500 space-y-3">
            {/*Server-side pagination — renders only PAGE_SIZE rows at a time */}
            <ThreatTable ref={tableRef} threats={threats} />
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-1 pt-1">
                <span className="text-xs text-slate-500 font-mono">
                  {totalThreats} total · page {currentPage}/{totalPages}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={currentPage <= 1}
                    onClick={() => handlePageChange(currentPage - 1)}
                    className="h-7 px-2 bg-transparent border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-30"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={currentPage >= totalPages}
                    onClick={() => handlePageChange(currentPage + 1)}
                    className="h-7 px-2 bg-transparent border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-30"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
