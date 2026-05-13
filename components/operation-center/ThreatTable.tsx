'use client'

import React, { useState } from 'react'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ShieldAlert, ChevronDown, ChevronRight, ServerCrash, Terminal, Radio, Loader2, Target, Hash } from 'lucide-react'
import { LiveTerminal } from './LiveTerminal'
import { useSocket } from '@/hooks/use-socket'

export function ThreatTable({ threats }: { threats: any[] }) {
  const { socket } = useSocket()
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({})
  const [killingBssids, setKillingBssids] = useState<Record<string, boolean>>({})

  const toggleRow = (id: string) => {
    setExpandedRows(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const handleKill = (e: React.MouseEvent, threat: any) => {
    e.stopPropagation()
    if (killingBssids[threat.source_mac]) return;

    if (socket) {
      setKillingBssids(prev => ({ ...prev, [threat.source_mac]: true }))
      socket.emit('kill_attack', { 
        bssid: threat.source_mac, 
        sensor_id: threat.detected_by || threat.mitigated_by_sensor_id || 1,
        operator_id: 'soc_operator'
      })
      setTimeout(() => {
        setKillingBssids(prev => ({ ...prev, [threat.source_mac]: false }))
      }, 3000)
    }
  }

  const getSeverityBadge = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === 'CRITICAL') return <Badge className="bg-red-500/10 text-red-400 border border-red-500/20 shadow-none rounded-sm">CRITICAL</Badge>
    if (s === 'HIGH') return <Badge className="bg-orange-500/10 text-orange-400 border border-orange-500/20 shadow-none rounded-sm">HIGH</Badge>
    if (s === 'MEDIUM') return <Badge className="bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 shadow-none rounded-sm">MEDIUM</Badge>
    if (s === 'LOW') return <Badge className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-none rounded-sm">LOW</Badge>
    return <Badge className="bg-slate-500/10 text-slate-400 border border-slate-500/20 shadow-none rounded-sm">INFO</Badge>
  }

  const getScoreColor = (score: number | string | undefined) => {
    const s = Number(score);
    if (isNaN(s)) return 'text-slate-400';
    if (s >= 80) return 'text-red-400';
    if (s >= 50) return 'text-orange-400';
    return 'text-emerald-400';
  }

  const getStatusIndicator = (status: string, severity?: string) => {
    const s = status?.toUpperCase();
    const sev = severity?.toUpperCase();

    if (s === 'ATTACKING') return (
      <div className="flex items-center gap-2">
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500"></span>
        </span>
        <span className="text-red-400 font-semibold text-xs tracking-wider">ATTACKING</span>
      </div>
    )
    if (s === 'KILLED') return <span className="text-slate-500 text-xs tracking-wider">KILLED</span>
    if (s === 'EVALUATING' || (s === 'IDLE' && (sev === 'MEDIUM' || sev === 'HIGH' || sev === 'CRITICAL'))) return (
      <div className="flex items-center gap-2">
        <span className="relative flex h-2 w-2">
          <span className="animate-pulse absolute inline-flex h-full w-full rounded-full bg-yellow-400 opacity-60"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-yellow-500"></span>
        </span>
        <span className="text-yellow-400 text-xs tracking-wider">EVALUATING</span>
      </div>
    )
    if (s === 'MONITORING') return (
      <div className="flex items-center gap-2">
        <span className="relative flex h-2 w-2">
          <span className="animate-pulse absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-60"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
        </span>
        <span className="text-blue-400 text-xs tracking-wider">MONITORING</span>
      </div>
    )
    return <span className="text-emerald-500/70 text-xs tracking-wider">IDLE</span>
  }

  return (
    <div className="rounded-xl border border-emerald-500/10 bg-slate-900/40 backdrop-blur-md overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="border-b border-emerald-500/10 hover:bg-transparent">
            <TableHead className="w-[40px]"></TableHead>
            <TableHead className="text-emerald-500/60 font-medium text-xs uppercase tracking-widest">Date & Time</TableHead>
            <TableHead className="text-emerald-500/60 font-medium text-xs uppercase tracking-widest">Severity</TableHead>
            <TableHead className="text-emerald-500/60 font-medium text-xs uppercase tracking-widest">Target SSID</TableHead>
            <TableHead className="text-emerald-500/60 font-medium text-xs uppercase tracking-widest">MAC Address</TableHead>
            <TableHead className="text-emerald-500/60 font-medium text-xs uppercase tracking-widest text-center">Hits</TableHead>
            <TableHead className="text-emerald-500/60 font-medium text-xs uppercase tracking-widest">Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {threats.map((threat) => {
            const isExpanded = expandedRows[threat.id]
            const isAttacking = threat.action_status === 'ATTACKING'
            const isKilling = killingBssids[threat.source_mac]

            return (
              <React.Fragment key={threat.id}>
                <TableRow 
                  onClick={() => toggleRow(threat.id)}
                  className={`cursor-pointer border-b border-emerald-500/5 transition-all duration-200 
                    ${isExpanded ? 'bg-emerald-500/5' : 'hover:bg-slate-800/50'}
                    ${isAttacking ? 'bg-red-950/10 border-l-2 border-l-red-500' : 'border-l-2 border-l-transparent'}
                  `}
                >
                  <TableCell className="pl-4">
                    {isExpanded ? <ChevronDown className="h-4 w-4 text-emerald-500" /> : <ChevronRight className="h-4 w-4 text-emerald-500/50" />}
                  </TableCell>
                  <TableCell className="text-slate-400 whitespace-nowrap font-mono text-[10px] leading-tight">
                    {(() => {
                      // Force UTC interpretation by adding 'Z' if missing, then convert to local
                      const dateStr = threat.created_at;
                      const date = new Date(dateStr.endsWith('Z') || dateStr.includes('+') ? dateStr : dateStr + 'Z');
                      return (
                        <>
                          <div className="text-emerald-500/60">{date.toLocaleDateString([], {day: '2-digit', month: '2-digit'})}</div>
                          <div>{date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'})}</div>
                        </>
                      );
                    })()}
                  </TableCell>
                  <TableCell>
                    {getSeverityBadge(threat.severity)}
                  </TableCell>
                  <TableCell className="font-medium text-emerald-50 text-sm">
                    {threat.ssid || '<Hidden Network>'}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5 font-mono text-xs text-slate-400 bg-slate-950/50 px-2 py-1 rounded w-fit border border-slate-800">
                      <Hash className="w-3 h-3 text-emerald-500/40" />
                      {threat.source_mac}
                    </div>
                  </TableCell>
                  <TableCell className="text-center">
                    <span className="font-mono text-xs font-semibold text-emerald-400/80">
                      {threat.threat_count || 1}
                    </span>
                  </TableCell>
                  <TableCell>
                    {getStatusIndicator(threat.action_status)}
                  </TableCell>
                </TableRow>
                
                {isExpanded && (
                  <TableRow className="bg-[#050B14]">
                    <TableCell colSpan={7} className="p-0 border-b border-emerald-500/10">
                      
                      {/* Target HUD - Clean and Organized Panel */}
                      <div className="p-6 grid grid-cols-1 xl:grid-cols-3 gap-6">
                        
                        {/* Terminal Area (2/3 width) */}
                        <div className="xl:col-span-2 flex flex-col bg-black rounded-lg border border-emerald-500/20 overflow-hidden relative shadow-inner">
                          {/* Terminal Header */}
                          <div className="bg-slate-950 px-4 py-2 border-b border-emerald-500/20 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Terminal className="h-4 w-4 text-emerald-500" />
                              <span className="text-xs font-mono text-emerald-500/80 uppercase tracking-widest">Containment Protocol Logs</span>
                            </div>
                            <div className="flex gap-1.5">
                              <div className="w-2.5 h-2.5 rounded-full bg-slate-800"></div>
                              <div className="w-2.5 h-2.5 rounded-full bg-slate-800"></div>
                              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/50"></div>
                            </div>
                          </div>
                          {/* Terminal Content */}
                          <div className="flex-1 p-2">
                            <LiveTerminal bssid={threat.source_mac} />
                          </div>
                        </div>

                        {/* Intelligence & Action Area (1/3 width) */}
                        <div className="flex flex-col gap-4">
                          
                          {/* Threat Intel Card */}
                          <div className="bg-slate-900/50 border border-emerald-500/10 rounded-lg p-5 flex-1 flex flex-col">
                            <h4 className="text-xs font-semibold text-emerald-500/50 uppercase tracking-widest flex items-center gap-2 mb-4">
                              <Target className="h-4 w-4" />
                              Target Intelligence
                            </h4>
                            
                            <div className="grid grid-cols-2 gap-y-4 gap-x-2 text-sm">
                              <div>
                                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Channel</div>
                                <span className="font-mono text-slate-200">{threat.channel || '--'}</span>
                              </div>
                              <div>
                                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Signal (RSSI)</div>
                                <span className="font-mono text-slate-200">{threat.signal ? `${threat.signal} dBm` : '--'}</span>
                              </div>
                              <div>
                                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Encryption</div>
                                <span className="font-mono text-slate-200">{threat.encryption || 'OPEN'}</span>
                              </div>
                              <div>
                                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Risk Score</div>
                                <span className={`font-mono font-bold ${getScoreColor(threat.risk_score)}`}>{threat.risk_score || '--'}<span className="text-slate-600 text-xs font-normal">/100</span></span>
                              </div>
                              <div className="col-span-2">
                                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Detected By Node</div>
                                <span className="font-mono text-emerald-400/80 text-xs bg-emerald-950/30 px-2 py-1 rounded inline-flex items-center gap-2 border border-emerald-500/10">
                                  <Radio className="w-3 h-3" />
                                  ID: {threat.detected_by || threat.mitigated_by_sensor_id || 'Unknown'}
                                </span>
                              </div>
                              <div className="col-span-2 mt-2">
                                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Signature Description</div>
                                <div className="text-slate-300 text-xs leading-relaxed">{threat.description}</div>
                              </div>
                            </div>
                          </div>
                          
                          {/* Emergency Action */}
                          <div className="bg-red-950/10 border border-red-500/20 rounded-lg p-4">
                            <Button 
                              variant="destructive" 
                              className={`w-full h-12 flex items-center justify-center gap-2 font-bold tracking-wide uppercase transition-all ${
                                !isAttacking ? 'bg-slate-800 text-slate-500 hover:bg-slate-800 cursor-not-allowed' : 
                                isKilling ? 'bg-red-900 text-red-300 cursor-not-allowed' : 'bg-red-600 hover:bg-red-500 hover:shadow-[0_0_20px_rgba(220,38,38,0.4)]'
                              }`}
                              onClick={(e) => (isAttacking && !isKilling) ? handleKill(e, threat) : e.stopPropagation()}
                              disabled={!isAttacking || isKilling}
                            >
                              {isKilling ? (
                                <><Loader2 className="h-5 w-5 animate-spin" /> EXECUTING KILL...</>
                              ) : (
                                <><ServerCrash className="h-5 w-5" /> EMERGENCY KILL</>
                              )}
                            </Button>
                          </div>

                        </div>

                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </React.Fragment>
            )
          })}
          {threats.length === 0 && (
            <TableRow>
              <TableCell colSpan={7} className="h-32 text-center text-slate-500 font-mono text-sm">
                No active signatures found in matrix.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  )
}