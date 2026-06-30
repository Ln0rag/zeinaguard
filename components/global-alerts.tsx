'use client';

import { useRef, useCallback } from 'react';
import { toast } from 'sonner';
import { useSocket } from '@/hooks/use-socket';
import type { EvilTwinSuspectedEvent, TrustedApAnomalyEvent } from '@/hooks/use-socket';
import { useSensorStore } from '@/hooks/use-sensor-store';
import { useAlertStore } from '@/hooks/use-alert-store';

const alertedRoguesCache = new Set<string>();
const alertedEvilTwinsCache = new Set<string>();

export function GlobalAlerts() {
  const latestTelemetryRef = useRef<any>(null);
  const prevSensorStatusRef = useRef<string | null>(null);
  const addLog = useSensorStore((state) => state.addLog);
  const addNotification = useAlertStore((state) => state.addNotification);
  const lastNotifRef = useRef<{type: string, bssid: string, time: number} | null>(null);
  const networksCacheRef = useRef<Map<string, any>>(new Map());
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
      addNotification({ type, title, ...data });
    } catch (err) {}

    const toastOptions = { description, duration: type === 'rogue' ? 10000 : 5000 };
    if (type === 'rogue') toast.error(title, toastOptions);
    else if (type === 'attack_start') toast.success(title, toastOptions);
    else if (type === 'attack_end') toast.info(title, toastOptions);
    else toast.warning(title, toastOptions);
  }, [playAlertSound]);

  const handleEvilTwinSuspected = useCallback((event: EvilTwinSuspectedEvent) => {
    const bssid = String(event.bssid || '').toUpperCase();

    if (alertedEvilTwinsCache.has(bssid)) return;

    const netInfo = networksCacheRef.current.get(bssid) || {};
    const channel = event.channel ?? netInfo.channel ?? null;
    const signal = event.signal ?? netInfo.signal ?? null;
    const trustedOriginals = Array.isArray(event.trusted_originals) ? event.trusted_originals : [];
    const knownBssids = Array.isArray(event.known_bssids) ? event.known_bssids : [];
    const confidence = event.is_high_confidence ? ' · High Confidence' : '';
    const knownList =
      trustedOriginals.length > 0
        ? `Legitimate AP: ${trustedOriginals[0]}`
        : knownBssids.length > 0
          ? `Known BSSIDs: ${knownBssids.slice(0, 2).join(', ')}`
          : 'SSID collision detected';
    alertedEvilTwinsCache.add(bssid);

    triggerAlert(
      'rogue',
      'CRITICAL: Evil Twin Suspected!',
      `SSID "${event.ssid || 'Hidden'}" spoofed by ${bssid}${confidence} — ${knownList}`,
      { bssid, ssid: event.ssid || 'Hidden', channel, signal },
    );
  }, [triggerAlert]);

  const handleTrustedApAnomaly = useCallback((event: TrustedApAnomalyEvent) => {
    const bssid = String(event.bssid || '').toUpperCase();
    const kindLabel =
      event.anomaly_kind === 'channel_change' ? 'Channel Drift' : 'Security Degradation';
    const detail =
      event.anomaly_kind === 'channel_change'
        ? `Ch ${event.baseline_value} → Ch ${event.current_value}`
        : `${event.baseline_value} → ${event.current_value}`;
    const trustTag = event.is_trusted ? ' [Trusted AP]' : '';

    const isCritical = event.is_trusted && event.anomaly_kind === 'security_degradation';
    const alertType = isCritical ? 'rogue' : 'warning';
    const alertTitle = isCritical
      ? 'CRITICAL: Trusted AP Security Downgrade'
      : 'Trusted AP Anomaly Detected';

    triggerAlert(
      alertType,
      alertTitle,
      `${kindLabel}${trustTag} on ${bssid} (${event.ssid || 'Hidden'}) — ${detail}`,
      { bssid, ssid: event.ssid || 'Hidden' },
    );
  }, [triggerAlert]);

  const handleTrustedWeakEncryption = useCallback((event: any) => {
    const bssid = String(event.bssid || '').toUpperCase();
    const netInfo = networksCacheRef.current.get(bssid) || {};
    const channel = event.channel ?? netInfo.channel ?? null;
    const signal = event.signal ?? netInfo.signal ?? null;
    const manufacturer = event.manufacturer ?? netInfo.manufacturer ?? null;

    const ssid = event.ssid || 'Hidden';
    const encryption = event.current_encryption || 'UNKNOWN';
    const severity = event.severity || 'warning';
    
    const isCritical = severity === 'critical';
    const alertType = isCritical ? 'rogue' : 'warning';
    const title = isCritical 
        ? 'CRITICAL: Trusted Network is OPEN/WEAK!' 
        : 'Trusted Network Using Weak Encryption';
    
    const description = event.message || 
        `Network "${ssid}" is using ${encryption}. Please change to WPA2/WPA3!`;

    triggerAlert(
        alertType,
        title,
        description,
        { bssid, ssid, encryption, severity, channel, signal, manufacturer },
    );
  }, [triggerAlert]);

  const handleStatusChange = useCallback((newStatus: string, data: any) => {
    if (statusTimeoutRef.current) clearTimeout(statusTimeoutRef.current);
    
    latestTelemetryRef.current = data;

    const isOnline = newStatus === 'online' || newStatus === 'monitoring' || newStatus === 'capturing' || newStatus === 'analyzing';
    const isError = newStatus === 'error' || newStatus === 'warning';
    const isOffline = newStatus === 'offline';
    
    const prevStatus = prevSensorStatusRef.current;
    
    if (prevStatus === null) {
      if (isOffline) prevSensorStatusRef.current = 'offline';
      else if (isError) prevSensorStatusRef.current = 'error';
      else prevSensorStatusRef.current = 'online';
      return;
    }

    if (isOnline) {
      if (prevStatus === 'offline') {
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
      } else if (prevStatus === 'error') {
        // Adapter Restored
        statusTimeoutRef.current = setTimeout(() => {
          const finalData = latestTelemetryRef.current || data;
          const sensorId = String(finalData.sensor_id || '1');
          triggerAlert('attack_start', 'ADAPTER RESTORED', `Radio adapter ${finalData.interface || 'wlan1'} recovered.`, {
             sensor_id: sensorId,
             hostname: finalData.hostname || 'linux',
             interface: finalData.interface || 'wlan1',
             uptime: typeof finalData.uptime === 'number' ? finalData.uptime : Number(finalData.uptime || 0),
             bssid: `ID: #${sensorId}`,
             ssid: 'Infrastructure'
          });
          prevSensorStatusRef.current = 'online';
        }, 2000);
      }
      return;
    }

    if (isError) {
      if (prevStatus === 'online') {
        // Adapter Failure
        statusTimeoutRef.current = setTimeout(() => {
          const sensorId = String(data.sensor_id || '1');
          triggerAlert('rogue', 'ADAPTER FAILURE', `Radio failure on ${data.interface || 'wlan1'}!`, {
            sensor_id: sensorId,
            hostname: data.hostname || 'linux',
            interface: data.interface || 'wlan1',
            uptime: typeof data.uptime === 'number' ? data.uptime : Number(data.uptime || 0),
            bssid: `ID: #${sensorId}`,
            ssid: 'Infrastructure'
          });
          prevSensorStatusRef.current = 'error';
        }, 3000);
      } else if (prevStatus === 'offline') {
        // Reconnected but with an adapter error immediately.
        prevSensorStatusRef.current = 'error';
      }
      return;
    }

    if (isOffline) {
      if (prevStatus !== 'offline') {
        // (Sensor Offline)
        statusTimeoutRef.current = setTimeout(() => {
          const sensorId = String(data.sensor_id || '1');
          triggerAlert('rogue', 'SENSOR OFFLINE', `Critical: Sensor #${sensorId} disconnected!`, {
            sensor_id: sensorId,
            hostname: data.hostname || 'linux',
            interface: data.interface || 'wlan1',
            uptime: typeof data.uptime === 'number' ? data.uptime : Number(data.uptime || 0),
            bssid: `ID: #${sensorId}`,
            ssid: 'Infrastructure'
          });
          prevSensorStatusRef.current = 'offline';
        }, 3000); 
      }
      return;
    }
  }, [triggerAlert]);

  useSocket({
    onSensorStatusUpdate: (event: any) => {
      const data = event?.data || {};
      const status = data.status || "offline";
      handleStatusChange(status, data);
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
      alertedEvilTwinsCache.delete(bssid);
    },

    onAttackCommand: (event: any) => {
      const bssidStr = String(event.bssid).toUpperCase();
      const netInfo = networksCacheRef.current.get(bssidStr) || {};
      
      const attackData = {
        bssid: event.bssid,
        ssid: netInfo.ssid || 'Hidden Network',
        target: netInfo.ssid || 'Hidden Network',
        channel: event.channel || netInfo.channel,
        signal: netInfo.signal,
        manufacturer: netInfo.manufacturer || 'Unknown Mfr'
      };

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
          target: netInfo.ssid || 'Hidden Network',
          channel: event.channel || netInfo.channel,
          signal: netInfo.signal,
          manufacturer: netInfo.manufacturer || 'Unknown Mfr'
        };

        setTimeout(() => {
          triggerAlert('attack_start', 'ATTACK DISPATCHED', `Targeting ${attackData.ssid}`, attackData);
        }, 400);
      }
    },

    onEvilTwinSuspected: handleEvilTwinSuspected,

    onTrustedApAnomaly: handleTrustedApAnomaly,

    onTrustedWeakEncryption: handleTrustedWeakEncryption,

      
    onThreatEvent: (event: any) => {
      if (event.data?.threat_type === 'deauth_attack') {
        const data = event.data;
        const bssidStr = String(data.source_mac || '').toUpperCase();
        
        const netInfo = networksCacheRef.current.get(bssidStr) || {};
        
        const ssid = data.ssid || netInfo.ssid || 'Unknown Network';
        
        triggerAlert(
          'rogue',
          'DEAUTH ATTACK DETECTED',
          `Trusted network "${ssid}" under deauthentication attack | ${data.description || ''}`,
          { 
            bssid: bssidStr, 
            target: ssid,
            ssid: ssid,
            channel: netInfo.channel || null,
            signal: netInfo.signal || null,
            manufacturer: netInfo.manufacturer || 'Attacker'
          }
        );
      }
    },

    onAttackAck: (event: any) => {
      const status = (event.status || '').toLowerCase();
      const bssidStr = String(event.bssid).toUpperCase();
      const netInfo = networksCacheRef.current.get(bssidStr) || {};
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