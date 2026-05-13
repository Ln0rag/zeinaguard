'use client'

import React, { useEffect, useState, useRef, memo } from 'react'
import { useSocket } from '@/hooks/use-socket'
import { ScrollArea } from '@/components/ui/scroll-area'

interface LiveTerminalProps {
  bssid: string
}

interface LogEntry {
  timestamp?: string
  message?: string
  [key: string]: any
}

export const LiveTerminal = memo(({ bssid }: LiveTerminalProps) => {
  const { isConnected, socket } = useSocket()
  const [logs, setLogs] = useState<LogEntry[]>([])
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!socket) return

    const handleLogHistory = (payload: any) => {
      if (payload.bssid === bssid && payload.history) {
        setLogs(payload.history)
      }
    }

    // التعديل: استلام اللوج المخصص للـ BSSID ده فقط بدون الحاجة لـ Filter
    const handleNewLog = (payload: any) => {
      setLogs(prev => {
        const newLogs = [...prev, payload]
        return newLogs.slice(-100) 
      })
    }

    socket.on('log_history_response', handleLogHistory)
    // بنسمع على الـ Event الخاص بالـ Room دي بس
    socket.on('deauth_log_specific', handleNewLog)

    // إخبار الباك إند إننا عايزين نشترك في لوجات الـ BSSID ده بس
    socket.emit('join_terminal', { bssid })
    
    // طلب التاريخ القديم
    socket.emit('request_log_history', { bssid })

    return () => {
      socket.off('log_history_response', handleLogHistory)
      socket.off('deauth_log_specific', handleNewLog)
    }
  }, [socket, bssid])

  useEffect(() => {
    // Auto-scroll to bottom seamlessly
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  return (
    <div className="rounded-md bg-black border border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.1)_inset] p-2 relative flex flex-col h-72 font-mono text-sm w-full">
      <div className="absolute top-2 right-2 flex items-center gap-2 z-10">
        <span className="text-xs text-emerald-500/50 uppercase font-bold tracking-widest bg-black/80 px-1">Terminal</span>
        <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-500 shadow-[0_0_5px_rgba(16,185,129,0.8)]' : 'bg-red-500 shadow-[0_0_5px_rgba(239,68,68,0.8)]'}`} />
      </div>
      <ScrollArea className="flex-1 mt-6 pr-3">
        {logs.length === 0 ? (
          <div className="text-emerald-500/40 italic mt-2 ml-2 text-xs">Waiting for containment logs...</div>
        ) : (
          <div className="flex flex-col gap-1 p-2 pb-4">
            {logs.map((log, i) => {
              const displayTime = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()
              const msg = log.message || JSON.stringify(log)
              return (
                // استخدام الـ index كجزء أساسي مع الـ timestamp الثابت بيمنع الـ Re-render الوهمي
                <div key={`term-log-${log.timestamp || 'local'}-${i}`} className="text-emerald-400 text-xs break-all drop-shadow-[0_0_2px_rgba(16,185,129,0.5)] leading-relaxed">
                  <span className="text-emerald-500/50 mr-2">[{displayTime}]</span>
                  {msg}
                </div>
              )
            })}
            <div ref={endRef} className="h-1" />
          </div>
        )}
      </ScrollArea>
    </div>
  )
})

LiveTerminal.displayName = 'LiveTerminal'