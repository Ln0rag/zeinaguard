'use client';

import { useRef, useCallback } from 'react';
import { toast } from 'sonner';
import { useSocket } from '@/hooks/use-socket';
import { useSensorStore } from '@/hooks/use-sensor-store';


// ذاكرة الشبكات الروق - مفيش مسح فوري بعد كده
const alertedRoguesCache = new Set<string>();

export function GlobalAlerts() {
  const latestTelemetryRef = useRef<any>(null); // لحفظ آخر تحديث شامل للبيانات
  const prevSensorStatusRef = useRef<string | null>(null);
  const addLog = useSensorStore((state) => state.addLog);
  const lastNotifRef = useRef<{type: string, bssid: string, time: number} | null>(null);
  const networksCacheRef = useRef<Map<string, any>>(new Map()); // ذاكرة لحفظ تفاصيل الشبكات عشان نستخدمها في الأتاك
  
  // مؤقت لمنع التذبذب (Anti-Flicker Timer)
  const statusTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const playAlertSound = useCallback(() => {
    try {
      const audio = new Audio('/system-notification.mp3');
      audio.play().catch(() => {});
    } catch (err) {}
  }, []);

  const triggerAlert = useCallback((type: string, title: string, description: string, data: any) => {
    const now = Date.now();
    if (lastNotifRef.current && lastNotifRef.current.type === type && lastNotifRef.current.bssid === data.bssid && (now - lastNotifRef.current.time) < 3000) return; 

    lastNotifRef.current = { type, bssid: data.bssid, time: now };
    playAlertSound();

    try {
      const newNotification = { type, title, ...data, id: Math.random().toString(36).substr(2, 9), time: new Date().toLocaleTimeString() };
      const saved = localStorage.getItem('zeinaguard_alerts');
      let parsed = [];
      if (saved) { try { parsed = JSON.parse(saved); } catch (e) { parsed = []; } }
      
      const updated = [newNotification, ...parsed].slice(0, 50);
      localStorage.setItem('zeinaguard_alerts', JSON.stringify(updated));
      localStorage.setItem('zeinaguard_unread_status', 'true');
      
      window.dispatchEvent(new CustomEvent('zeinaguard_new_notification'));
    } catch (err) {}

    const toastOptions = { description, duration: type === 'rogue' ? 10000 : 5000 };
    if (type === 'rogue') toast.error(title, toastOptions);
    else if (type === 'attack_start') toast.success(title, toastOptions);
    else if (type === 'attack_end') toast.info(title, toastOptions);
    else toast.warning(title, toastOptions);
  }, [playAlertSound]);

  const handleStatusChange = useCallback((newStatus: string, data: any) => {
    if (statusTimeoutRef.current) clearTimeout(statusTimeoutRef.current);
    
    // تحديث البيانات المستلمة دايماً عشان نستخدم أحدث نسخة
    latestTelemetryRef.current = data;

    const isOnline = newStatus === 'online' || newStatus === 'monitoring';
    const wasOffline = prevSensorStatusRef.current === 'offline';

    // التعامل مع حالة الأونلاين
    if (isOnline) {
      if (wasOffline) {
        // حالة العودة (Restored): هنستنى ثانيتين عشان نضمن إن التيليمتري (الأب تايم) وصل كامل
        statusTimeoutRef.current = setTimeout(() => {
          const finalData = latestTelemetryRef.current || data;
          const sensorId = String(finalData.sensor_id || '1');

          if (finalData.hostname && finalData.interface) {
            const sensorInfo = {
              sensor_id: sensorId,
              hostname: finalData.hostname,
              interface: finalData.interface,
              uptime: typeof finalData.uptime === 'number' ? finalData.uptime : Number(finalData.uptime || 0),
              bssid: `ID: #${sensorId}`,
              ssid: 'Infrastructure'
            };
            
            alertedRoguesCache.clear(); 
            triggerAlert('attack_start', 'SENSOR RESTORED', `Sensor #${sensorId} reconnected with full telemetry.`, sensorInfo);
            prevSensorStatusRef.current = 'online';
          }
        }, 2000);
      } else {
        // 🚀 الحل هنا: لو دي أول تحميله للصفحة والسنسور كان شغال، لازم نسجله في الذاكرة إنه 'online' 
        prevSensorStatusRef.current = 'online';
      }
      return; 
    }

    // حالة الفصل (Offline): بنفضل مستنيين 3 ثواني للتأكد إنها مش هزة كهرباء
    statusTimeoutRef.current = setTimeout(() => {
      if (newStatus === 'offline' && prevSensorStatusRef.current !== 'offline') {
        
        // التنبيه يشتغل فقط لو السنسور كان شغال (online) وفصل
        if (prevSensorStatusRef.current === 'online') {
          const sensorId = String(data.sensor_id || '1');
          triggerAlert('rogue', 'SENSOR OFFLINE', `Critical: Sensor #${sensorId} disconnected!`, {
            sensor_id: sensorId,
            hostname: data.hostname || 'linux',
            interface: data.interface || 'wlan1',
            uptime: typeof data.uptime === 'number' ? data.uptime : Number(data.uptime || 0),
            bssid: `ID: #${sensorId}`,
            ssid: 'Infrastructure'
          });
        }

        prevSensorStatusRef.current = 'offline';
      }
    }, 3000); 
  }, [triggerAlert]);

  useSocket({
    onSensorStatusUpdate: (event: any) => {
      const data = event?.data || {};
      const msg = (data.message || "").toLowerCase();
      const isHardwareOffline = msg.includes("disconnected") || msg.includes("removed") || msg.includes("error") || msg.includes("lost");
      const status = isHardwareOffline ? "offline" : (data.status || "offline");
      handleStatusChange(status, data);

      // 🔥 تسجيل السجلات في الرامات (Global State) بسرعة بدون تهنيج
      const sensorId = Number(data.sensor_id || data.id || 0);
      if (sensorId && data.message) {
        addLog(sensorId, data.message);
      }
    },
    
    onNetworkSnapshot: (event: any) => {
      const incoming = event.data || [];
      incoming.forEach((net: any) => {
        const bssid = String(net.bssid || '').toUpperCase();
        
        networksCacheRef.current.set(bssid, net);

        if (net.classification === 'ROGUE' && !alertedRoguesCache.has(bssid)) {
          alertedRoguesCache.add(bssid);
          
          const cleanNetworkData = {
            bssid, 
            ssid: net.ssid || 'Hidden', 
            channel: net.channel, 
            signal: net.signal, 
            // حطينا القيمة البديلة هنا عشان السطر يترسم دايماً
            manufacturer: net.manufacturer || 'Unknown Mfr'
          };
          triggerAlert('rogue', 'ROGUE DETECTED', `Target: ${cleanNetworkData.ssid}`, cleanNetworkData);
        } else if (net.classification !== 'ROGUE' && alertedRoguesCache.has(bssid)) {
          alertedRoguesCache.delete(bssid);
        }
      });
    },

    onNetworkRemoved: (event) => {
      const bssid = String(event.bssid || '').toUpperCase();
      alertedRoguesCache.delete(bssid);
    },

    onAttackCommand: (event: any) => {
      const bssidStr = String(event.bssid).toUpperCase();
      const netInfo = networksCacheRef.current.get(bssidStr) || {};
      
      const attackData = {
        bssid: event.bssid,
        ssid: netInfo.ssid || 'Hidden Network',
        target: netInfo.ssid || 'Hidden Network', // إجبار التارجت إنه ياخد الاسم مش الماك
        channel: event.channel || netInfo.channel,
        signal: netInfo.signal,
        manufacturer: netInfo.manufacturer || 'Unknown Mfr'
      };

      // تأخير 400 ملي ثانية عشان لو فيه أتاك قديم بيقف (Halted) يتسجل هو الأول في القائمة
      setTimeout(() => {
        triggerAlert('attack_start', 'ATTACK STARTED', `Target: ${attackData.ssid}`, attackData);
      }, 400);
    },

    onAttackCommandAck: (event: any) => {
      if (event.status === 'ok') {
        const bssidStr = String(event.bssid).toUpperCase();
        const netInfo = networksCacheRef.current.get(bssidStr) || {};
        
        const attackData = {
          bssid: event.bssid,
          ssid: netInfo.ssid || 'Hidden Network',
          target: netInfo.ssid || 'Hidden Network', // إجبار التارجت إنه ياخد الاسم
          channel: event.channel || netInfo.channel,
          signal: netInfo.signal,
          manufacturer: netInfo.manufacturer || 'Unknown Mfr'
        };

        setTimeout(() => {
          triggerAlert('attack_start', 'ATTACK DISPATCHED', `Targeting ${attackData.ssid}`, attackData);
        }, 400);
      }
    },

    onAttackAck: (event: any) => {
      const status = (event.status || '').toLowerCase();
      const bssidStr = String(event.bssid).toUpperCase();
      const netInfo = networksCacheRef.current.get(bssidStr) || {};

      // الاعتماد على الـ Cache (netInfo) أولاً لتجنب أي داتا خطأ جاية من الباك اند
      const attackData = {
        bssid: event.bssid,
        ssid: netInfo.ssid || event.ssid || 'Hidden Network',
        target: netInfo.ssid || event.ssid || 'Hidden Network',
        channel: netInfo.channel || event.channel,
        signal: netInfo.signal || event.signal,
        manufacturer: netInfo.manufacturer || event.manufacturer || 'Unknown Mfr'
      };

      if (['executed', 'finished', 'success', 'ok'].includes(status)) {
        triggerAlert('attack_end', 'ATTACK COMPLETED', `Target ${attackData.ssid} contained.`, attackData);
      } else if (status === 'aborted') {
        triggerAlert('attack_aborted', 'ATTACK HALTED', `Process stopped for ${attackData.ssid}.`, attackData);
      }
    }
  });

  return null;
}