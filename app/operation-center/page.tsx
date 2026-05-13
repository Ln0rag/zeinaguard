'use client'

import React, { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
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
import { Badge } from '@/components/ui/badge'
import { Download, ShieldAlert, ShieldCheck, Activity, Search, Filter, ListFilter, Trash2, AlertTriangle, FileText, Calendar } from 'lucide-react'
import { toast } from 'sonner'
import { ThreatTable } from '@/components/operation-center/ThreatTable'
import { useSocket } from '@/hooks/use-socket'
import { apiRequest } from '@/lib/api'

export interface ThreatType {
  id: number;
  threat_type: string;
  severity: string;
  source_mac: string;
  ssid: string;
  action_status: string;
  is_auto_mitigated: boolean;
  created_at: string;
  channel?: number;
  signal?: number;
  encryption?: string;
  risk_score?: number;
  detected_by?: string;
  mitigated_by_sensor_id?: string;
  threat_count?: number; 
}

interface KPIs {
  active: number;
  mitigated: number;
  total_actionable: number;
}

export default function OperationCenterPage() {
  const [threats, setThreats] = useState<ThreatType[]>([])
  const [kpis, setKpis] = useState<KPIs>({ active: 0, mitigated: 0, total_actionable: 0 })
  
  // المتغير الجديد اللي هيشيل عدد الأهداف المطابقة للفلتر
  const [filteredTotal, setFilteredTotal] = useState<number>(0)
  
  const [loading, setLoading] = useState(true)
  const { isConnected, socket } = useSocket()

  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ACTIONABLE')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [error, setError] = useState<string | null>(null)

  // Purge State
  const [purgeDialogOpen, setPurgeDialogOpen] = useState(false)
  const [purgeType, setPurgeType] = useState('today')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [lastPurgeReport, setLastPurgeReport] = useState<{name: string, url: string} | null>(null)
  const [isPurging, setIsPurging] = useState(false)

  const fetchThreats = React.useCallback(async () => {
    try {
      setError(null)
      const queryParams = new URLSearchParams({
        page: '1',
        limit: '200',
        search: searchQuery,
        severity: severityFilter,
        status: statusFilter
      });

      // استقبلنا الـ total من الباك إند
      const { data, error: apiError } = await apiRequest<{threats: ThreatType[], kpis: KPIs, total: number}>(`/api/operation-center/threats?${queryParams.toString()}`)
      
      if (apiError) throw new Error(apiError)
      if (data) {
        setThreats(data.threats || []);
        
        // ربطنا الرقم المتفلتر اللي جاي من الباك إند بالـ State بتاعنا
        setFilteredTotal(data.total || 0);

        if (data.kpis) {
          setKpis({
            active: data.kpis.active || 0,
            mitigated: data.kpis.mitigated || 0,
            total_actionable: data.kpis.total_actionable || 0
          });
        }
      }
    } catch (err: any) {
      setError(err.message || "Failed to load threats")
    } finally {
      setLoading(false)
    }
  }, [searchQuery, severityFilter, statusFilter])

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchThreats()
    }, 300)
    return () => clearTimeout(timer)
  }, [fetchThreats])

  useEffect(() => {
    if (!socket) return

    const handleReconnect = () => fetchThreats();

    const handleStateChange = (payload: any) => {
      setThreats(prev => {
        const hasThreat = prev.some(t => t.source_mac === payload.bssid)
        if (!hasThreat) return prev;

        return prev.map(t => {
          if (t.source_mac === payload.bssid) {
            return {
              ...t,
              action_status: payload.status || payload.to_state,
              is_auto_mitigated: ['ATTACKING', 'KILLED'].includes(payload.status || payload.to_state) ? true : t.is_auto_mitigated
            }
          }
          return t;
        })
      })
      
      if (payload.status === 'ATTACKING') {
        setKpis(prev => ({...prev, active: (prev?.active || 0) + 1}))
      } else if (payload.status === 'KILLED') {
        setKpis(prev => ({...prev, active: Math.max(0, (prev?.active || 0) - 1), mitigated: (prev?.mitigated || 0) + 1}))
      }
    }

    const handleThreatEvent = (payload: any) => {
      if ((payload.type === 'threat_detected' || payload.type === 'new_threat') && payload.data) {
        setThreats(prev => {
          const existingIndex = prev.findIndex(t => t.source_mac === payload.data.source_mac);
          if (existingIndex >= 0) {
            const updated = [...prev];
            updated[existingIndex] = {
              ...updated[existingIndex], 
              ...payload.data, 
              threat_count: (updated[existingIndex].threat_count || 1) + 1
            };
            const [item] = updated.splice(existingIndex, 1);
            return [item, ...updated];
          }
          
          setKpis(k => ({...k, total_actionable: (k?.total_actionable || 0) + 1}))
          setFilteredTotal(prev => prev + 1) // نزود العداد المتفلتر برضه عشان يفضل Real-time
          return [{...payload.data, threat_count: 1}, ...prev];
        });
      } else {
        fetchThreats()
      }
    }

    socket.emit('join_dashboard')
    socket.on('connect', handleReconnect)
    socket.on('attack_state_change', handleStateChange)
    socket.on('threat_event', handleThreatEvent)
    socket.on('threat_detected', handleThreatEvent)
    // استقبال إشارة التحديث من الباك إند لتحديث الكروت والجدول فوراً
    socket.on('stats_update_required', fetchThreats);
    
    return () => {
      socket.off('connect', handleReconnect)
      socket.off('attack_state_change', handleStateChange)
      socket.off('threat_event', handleThreatEvent)
      socket.off('threat_detected', handleThreatEvent)
      socket.off('stats_update_required', fetchThreats);
    }
  }, [socket, fetchThreats])

  const handleExport = (timeframe: string, format: string = 'csv') => {
    const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'
    window.open(`${baseUrl}/api/operation-center/export?timeframe=${timeframe}&format=${format}`, '_blank')
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

      const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'
      const response = await fetch(`${baseUrl}/api/operation-center/purge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || "Failed to purge database")
      }

      // Play alert sound immediately on this page
      try { new Audio('/system-notification.mp3').play().catch(() => {}) } catch (e) {}

      // Rich toast with download action
      const purgeLabel = purgeType === 'today' ? "Today's Records" : purgeType === 'weekly' ? 'Last 7 Days' : purgeType === 'monthly' ? 'Last 30 Days' : purgeType === 'all' ? 'All Records' : 'Custom Range'
      if (data.count > 0) {
        toast.success(`DATABASE PURGED — ${data.count} records`, {
          description: `Scope: ${purgeLabel}. Backup report generated.`,
          duration: 8000,
          action: {
            label: '📄 Download Report',
            onClick: () => window.open(`${baseUrl}${data.download_url}`, '_blank'),
          },
        })
        setLastPurgeReport({ name: data.report_name, url: data.download_url })
        
        // Push purge notification to the global alert system (Bell dropdown)
        try {
          const purgeNotification = {
            id: Math.random().toString(36).substr(2, 9),
            type: 'purge',
            title: 'DATABASE PURGED',
            time: new Date().toLocaleTimeString(),
            bssid: 'SYSTEM',
            ssid: 'Operation Center',
            purge_count: data.count,
            purge_type: purgeType,
            report_name: data.report_name,
            download_url: `${baseUrl}${data.download_url}`,
          }
          const saved = localStorage.getItem('zeinaguard_alerts')
          let parsed: any[] = []
          if (saved) { try { parsed = JSON.parse(saved) } catch (e) { parsed = [] } }
          const updated = [purgeNotification, ...parsed].slice(0, 50)
          localStorage.setItem('zeinaguard_alerts', JSON.stringify(updated))
          localStorage.setItem('zeinaguard_unread_status', 'true')
          window.dispatchEvent(new CustomEvent('zeinaguard_new_notification'))
        } catch (e) {}
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
                const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'
                window.open(`${baseUrl}${lastPurgeReport.url}`, '_blank')
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
                  {isPurging ? "Processing..." : "Confirm & Generate Report"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button className="bg-emerald-950/30 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10 hover:border-emerald-500/50 transition-all shadow-sm">
                <Download className="mr-2 h-4 w-4" />
                Export Reports
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-slate-900 border-emerald-500/20 text-emerald-100 shadow-2xl">
              <DropdownMenuItem onClick={() => handleExport('daily', 'csv')} className="focus:bg-emerald-500/10 cursor-pointer">Daily Export (CSV)</DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('weekly', 'csv')} className="focus:bg-emerald-500/10 cursor-pointer">Weekly Export (CSV)</DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('monthly', 'csv')} className="focus:bg-emerald-500/10 cursor-pointer">Monthly Export (CSV)</DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('all', 'csv')} className="focus:bg-emerald-500/10 cursor-pointer">All-Time (CSV)</DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('all', 'pdf')} className="focus:bg-emerald-500/10 cursor-pointer text-emerald-300">Generate Report (PDF)</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid gap-6 md:grid-cols-3">
        {/* Active Containments */}
        <Card className="relative overflow-hidden bg-slate-900/50 border-emerald-500/10 backdrop-blur-md group hover:border-red-500/30 transition-colors">
          <ShieldAlert className="absolute -right-6 -bottom-6 w-32 h-32 text-red-500/5 transform rotate-12 group-hover:text-red-500/10 transition-colors" />
          <CardHeader className="relative z-10 pb-2">
            <CardTitle className="text-xs font-semibold text-emerald-500/50 uppercase tracking-widest flex items-center gap-2">
              <span className={`w-1.5 h-1.5 rounded-full ${(kpis?.active || 0) > 0 ? 'bg-red-500 animate-pulse' : 'bg-emerald-500/30'}`}></span>
              Active Containments
            </CardTitle>
          </CardHeader>
          <CardContent className="relative z-10">
            <div className="text-4xl font-bold text-white tracking-tight">{kpis?.active || 0}</div>
            <p className="text-xs text-slate-500 mt-2 font-mono">Targets currently isolated</p>
          </CardContent>
        </Card>

        {/* Auto-Mitigated */}
        <Card className="relative overflow-hidden bg-slate-900/50 border-emerald-500/10 backdrop-blur-md">
          <ShieldCheck className="absolute -right-6 -bottom-6 w-32 h-32 text-emerald-500/5 transform rotate-12" />
          <CardHeader className="relative z-10 pb-2">
            <CardTitle className="text-xs font-semibold text-emerald-500/50 uppercase tracking-widest">Auto-Mitigated</CardTitle>
          </CardHeader>
          <CardContent className="relative z-10">
            <div className="text-4xl font-bold text-white tracking-tight">{kpis?.mitigated || 0}</div>
            <p className="text-xs text-slate-500 mt-2 font-mono">Historically contained</p>
          </CardContent>
        </Card>

        {/* Filtered Targets (العداد الديناميكي الجديد) */}
        <Card className="relative overflow-hidden bg-slate-900/50 border-emerald-500/10 backdrop-blur-md">
          <ListFilter className="absolute -right-6 -bottom-6 w-32 h-32 text-emerald-500/5 transform rotate-12" />
          <CardHeader className="relative z-10 pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-xs font-semibold text-emerald-500/50 uppercase tracking-widest">
              Filtered Targets
            </CardTitle>
          </CardHeader>
          <CardContent className="relative z-10">
            <div className="flex items-baseline gap-2">
              <div className="text-4xl font-bold text-white tracking-tight">
                {/* هنا بنعرض الرقم المتفلتر اللي بيتغير مع كل اكشن في الفلتر */}
                {filteredTotal}
              </div>
              <span className="text-sm text-slate-500 font-mono">Matching Results</span>
            </div>
            <p className="text-xs text-slate-500 mt-2 font-mono">
              Based on your active search & filters
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Live Threat Matrix Section */}
      <div className="space-y-4">
        {/* Sleek Command Strip Filter Bar */}
        <div className="flex flex-col lg:flex-row gap-3 bg-slate-900/60 p-2 rounded-lg border border-emerald-500/10 backdrop-blur-xl">
           <div className="relative flex-1">
             <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-emerald-500/40" />
             <Input 
               placeholder="Search BSSID or SSID..." 
               value={searchQuery}
               onChange={(e) => setSearchQuery(e.target.value)}
               className="pl-9 bg-transparent border-none text-emerald-50 focus-visible:ring-0 placeholder:text-emerald-500/30 font-mono text-sm h-10"
             />
           </div>
           
           <div className="w-px bg-emerald-500/10 hidden lg:block mx-1"></div>
           
           <div className="flex flex-col sm:flex-row gap-3 lg:w-[400px]">
             <Select value={severityFilter} onValueChange={setSeverityFilter}>
               <SelectTrigger className="bg-transparent border-none text-emerald-100 focus:ring-0 h-10 shadow-none hover:bg-slate-800/50">
                 <div className="flex items-center gap-2">
                   <Filter className="h-3.5 w-3.5 text-emerald-500/50" />
                   <SelectValue placeholder="Severity" />
                 </div>
               </SelectTrigger>
               <SelectContent className="bg-slate-900 border-emerald-500/20 text-emerald-100">
                 <SelectItem value="ACTIONABLE" className="text-red-400 font-bold bg-red-500/5">Actionable (High/Critical)</SelectItem>
                 <SelectItem value="ALL">All Severities</SelectItem>
                 <SelectItem value="CRITICAL" className="text-red-400">Critical Only</SelectItem>
                 <SelectItem value="HIGH" className="text-orange-400">High Only</SelectItem>
                 <SelectItem value="MEDIUM" className="text-yellow-400">Medium</SelectItem>
                 <SelectItem value="LOW" className="text-emerald-400">Low</SelectItem>
               </SelectContent>
             </Select>

             <div className="w-px bg-emerald-500/10 hidden sm:block"></div>

             <Select value={statusFilter} onValueChange={setStatusFilter}>
               <SelectTrigger className="bg-transparent border-none text-emerald-100 focus:ring-0 h-10 shadow-none hover:bg-slate-800/50">
                 <SelectValue placeholder="Action Status" />
               </SelectTrigger>
               <SelectContent className="bg-slate-900 border-emerald-500/20 text-emerald-100">
                 <SelectItem value="ALL">All Statuses</SelectItem>
                 <SelectItem value="ATTACKING" className="text-red-400">Attacking</SelectItem>
                 <SelectItem value="MONITORING">Monitoring</SelectItem>
                 <SelectItem value="EVALUATING">Evaluating</SelectItem>
                 <SelectItem value="RE_ARMING">Re-arming</SelectItem>
                 <SelectItem value="KILLED">Killed</SelectItem>
                 <SelectItem value="IDLE">Idle</SelectItem>
               </SelectContent>
             </Select>
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
          <div className="animate-in fade-in duration-500">
            <ThreatTable threats={threats} /> 
          </div>
        )}
      </div>
    </div>
  )
}