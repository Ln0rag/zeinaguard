'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';

export interface LiveNetworkEvent {
  ssid: string;
  bssid: string;
  channel: number | null;
  signal: number | null;
  classification: 'LEGIT' | 'SUSPICIOUS' | 'ROGUE';
  score: number;
  sensor_id: number;
  is_trusted: boolean;
  reasons: string[];
  frequency?: number | null;
  manufacturer?: string | null;
  timestamp?: string;
  last_seen: string;
  distance?: number | string;
  auth?: string | null;
  wps?: string | null;
  encryption?: string | null;
  uptime?: number | string | null;
  clients?: any[];
  clients_count?: number;
}

export interface NetworkSnapshotEvent {
  event: 'network_snapshot' | 'networks_snapshot';
  data: LiveNetworkEvent[];
}

export type NetworkSnapshotPayload =
  | NetworkSnapshotEvent
  | LiveNetworkEvent[];

export interface NetworkRemovedEvent {
  sensor_id?: number;
  bssid: string;
  timestamp?: string;
}

export interface ThreatEvent {
  type: 'threat_detected';
  timestamp: string;
  severity?: string;
  data: {
    id: number;
    threat_type: string;
    severity: string;
    source_mac: string;
    ssid: string;
    detected_by: number;
    description: string;
    signal_strength: number;
    packet_count: number;
    is_resolved: boolean;
    created_at: string;
  };
}

export interface SensorStatusEvent {
  sensor_id: number;
  status: string;
  cpu: number;
  memory: number;
  uptime: number;
  last_seen: string;
  last_heartbeat: string;
  message?: string | null;
  interface?: string | null;
  hostname?: string | null;
  connected?: boolean;
}

export interface SensorSnapshotEvent {
  event: 'sensor_snapshot';
  data: SensorStatusEvent[];
}

export interface SensorStatusUpdateEvent {
  event: 'sensor_status_update';
  data: SensorStatusEvent;
  isTransition?: boolean;
}

export interface AttackCommandEvent {
  sensor_id: number;
  bssid: string;
  action?: string;
  channel?: number | null;
  timestamp?: string;
  status?: string;
}

export interface AttackAckEvent {
  event: 'attack_ack';
  status: 'executed' | 'failed' | string;
  bssid: string;
  sensor_id: number;
  message?: string | null;
  timestamp: string;
  attack?: Record<string, unknown>;
}

export interface AttackCommandAckEvent {
  status: 'ok' | 'error';
  sensor_id?: number;
  bssid?: string;
  channel?: number | null;
  message?: string | null;
  timestamp: string;
}

export interface EvilTwinSuspectedEvent {
  bssid: string;
  ssid: string;
  channel?: number | null;
  signal?: number | null;
  known_bssids: string[];
  trusted_originals: string[];
  is_high_confidence: boolean;
  classification: string;
  score: number;
  timestamp: string;
}

export interface TrustedApAnomalyEvent {
  bssid: string;
  ssid: string;
  is_trusted: boolean;
  anomaly_kind: 'channel_change' | 'security_degradation';
  baseline_value: string | number;
  current_value: string | number;
  delta?: number;
  timestamp: string;
}

export interface TrustedWeakEncryptionEvent {
    bssid: string;
    ssid: string;
    current_encryption: string;
    expected_encryption: string;
    severity: 'critical' | 'warning';
    message: string;
    timestamp: string;
}

interface UseSocketOptions {
  onNetworkSnapshot?: (event: NetworkSnapshotEvent) => void;
  onSensorSnapshot?: (event: SensorSnapshotEvent) => void;
  onSensorStatusUpdate?: (event: SensorStatusUpdateEvent) => void;
  onNetworkRemoved?: (event: NetworkRemovedEvent) => void;
  onAttackCommand?: (event: AttackCommandEvent) => void;
  onAttackCommandAck?: (event: AttackCommandAckEvent) => void;
  onAttackAck?: (event: AttackAckEvent) => void;
  onThreatEvent?: (event: ThreatEvent) => void;
  onEvilTwinSuspected?: (event: EvilTwinSuspectedEvent) => void;
  onTrustedApAnomaly?: (event: TrustedApAnomalyEvent) => void;
  onTrustedWeakEncryption?: (event: TrustedWeakEncryptionEvent) => void;
  autoConnect?: boolean;
}

const SOCKET_EVENTS = [
  'network_snapshot',
  'networks_snapshot',
  'sensor_snapshot',
  'sensor_status_update',
  'network_removed',
  'threat_detected',
  'attack_command',
  'attack_command_ack',
  'attack_ack',
  'threat_event',
  'evil_twin_suspected',
  'trusted_ap_anomaly',
  'trusted_weak_encryption',
] as const;

function resolveSocketUrl(): string {
  return (
    process.env.NEXT_PUBLIC_SOCKET_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    process.env.NEXT_PUBLIC_BACKEND_URL ||
    ''
  );
}

function normalizeLastSeen(value: unknown): string {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const timestamp = value > 1_000_000_000_000 ? value : value * 1000;
    return new Date(timestamp).toISOString();
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^\d+$/.test(trimmed)) {
      const numericValue = Number(trimmed);
      const timestamp = numericValue > 1_000_000_000_000 ? numericValue : numericValue * 1000;
      return new Date(timestamp).toISOString();
    }
    const parsed = new Date(trimmed);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
  }
  return new Date().toISOString();
}

function normalizeClassification(value: unknown): LiveNetworkEvent['classification'] {
  const classification = String(value || 'LEGIT').trim().toUpperCase();
  if (classification === 'ROGUE' || classification === 'SUSPICIOUS') {
    return classification;
  }
  return 'LEGIT';
}

function normalizeClients(value: unknown): LiveNetworkEvent['clients'] {
  if (!Array.isArray(value)) return [];
  return value.map((client) => {
    if (!client || typeof client !== 'object') return null;
    const clientRecord = client as Record<string, unknown>;
    const mac = String(clientRecord.mac || '').trim().toUpperCase();
    if (!mac) return null;
    return {
      mac,
      type: String(clientRecord.type || 'device').trim().toLowerCase() || 'device',
    };
  }).filter((client): client is NonNullable<typeof client> => Boolean(client));
}

function normalizeNetworkItem(item: unknown): LiveNetworkEvent {
  const network = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>;
  const lastSeen = normalizeLastSeen(network.last_seen ?? network.timestamp);
  const clients = normalizeClients(network.clients);
  const rawClientsCount = network.clients_count ?? network.clients;
  const parsedClientsCount = Array.isArray(rawClientsCount) ? rawClientsCount.length : Number(rawClientsCount);
  const clientsCount = Number.isFinite(parsedClientsCount) ? Math.max(0, parsedClientsCount) : (clients ?? []).length;
  const manufacturer = network.manufacturer == null ? null : String(network.manufacturer).trim();
  const normalizedManufacturer =
    manufacturer && !['unknown', 'unknown mfr', 'none', 'n/a'].includes(manufacturer.toLowerCase())
      ? manufacturer
      : null;

  return {
    sensor_id: Number(network.sensor_id || 0),
    ssid: String(network.ssid || 'Hidden').trim() || 'Hidden',
    bssid: String(network.bssid || '').trim().toUpperCase().replace(/-/g, ':'),
    signal: typeof network.signal === 'number' ? network.signal : network.signal == null ? null : Number(network.signal),
    channel: typeof network.channel === 'number' ? network.channel : network.channel == null ? null : Number(network.channel),
    frequency: typeof network.frequency === 'number' ? network.frequency : network.frequency == null ? null : Number(network.frequency),
    classification: normalizeClassification(network.classification),
    
    score: Number(network.score || 0),
    is_trusted: Boolean(network.is_trusted || false),
    reasons: Array.isArray(network.reasons) ? network.reasons : [],
    
    last_seen: lastSeen,
    timestamp: typeof network.timestamp === 'string' ? network.timestamp : lastSeen,
    manufacturer: normalizedManufacturer,
    auth: (network.auth ?? network.auth_type) == null ? null : String(network.auth ?? network.auth_type),
    wps: (network.wps ?? network.wps_info) == null ? null : String(network.wps ?? network.wps_info),
    encryption: network.encryption == null ? null : String(network.encryption),
    uptime: (network.uptime ?? network.uptime_seconds ?? null) as string | number | null,
    clients,
    clients_count: clientsCount,
    distance: network.distance ? (typeof network.distance === 'number' ? network.distance : String(network.distance)) : undefined,
  };
}

function normalizeNetworkSnapshot(
  eventName: NetworkSnapshotEvent['event'],
  payload: NetworkSnapshotPayload,
): NetworkSnapshotEvent {
  if (Array.isArray(payload)) {
    return { event: eventName, data: payload.map(normalizeNetworkItem) };
  }
  return {
    event: payload.event ?? eventName,
    data: Array.isArray(payload.data) ? payload.data.map(normalizeNetworkItem) : [],
  };
}

export function useSocket(options: UseSocketOptions = {}) {
  const {
   onNetworkSnapshot,
   onSensorSnapshot,
   onSensorStatusUpdate,
   onNetworkRemoved,
   onAttackCommand,
   onAttackCommandAck,
   onAttackAck,
   onThreatEvent,
   onEvilTwinSuspected,
   onTrustedApAnomaly,
   onTrustedWeakEncryption,
   autoConnect = true,
 } = options;

const socketRef = useRef<Socket | null>(null);
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const previousSensorStatus = useRef<Record<number, string>>({});
  const handlersRef = useRef({
   onNetworkSnapshot,
   onSensorSnapshot,
   onSensorStatusUpdate,
   onNetworkRemoved,
   onAttackCommand,
   onAttackCommandAck,
   onAttackAck,
   onThreatEvent,
   onEvilTwinSuspected,
   onTrustedApAnomaly,
   onTrustedWeakEncryption,
 });

  useEffect(() => {
    handlersRef.current = {
      onNetworkSnapshot,
      onSensorSnapshot,
      onSensorStatusUpdate,
      onNetworkRemoved,
      onAttackCommand,
      onAttackCommandAck,
      onAttackAck,
      onThreatEvent,
      onEvilTwinSuspected,
      onTrustedApAnomaly,
      onTrustedWeakEncryption,
    };
  }, [onAttackAck, onAttackCommand, onAttackCommandAck, onNetworkRemoved, onNetworkSnapshot, onSensorSnapshot, onSensorStatusUpdate, onThreatEvent, onEvilTwinSuspected, onTrustedApAnomaly, onTrustedWeakEncryption]);

  const connect = useCallback(() => {
    if (socketRef.current) return;

    const socketUrl = resolveSocketUrl();
    const socketInstance = io(socketUrl, {
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity,
      timeout: 10000,
      transports: ['websocket', 'polling'],
      auth: {
        token: process.env.NEXT_PUBLIC_SOCKET_TOKEN || process.env.NEXT_PUBLIC_API_TOKEN || '',
      },
    });

    socketInstance.on('connect', () => {
      setConnected(true);
    });

    socketInstance.on('disconnect', (_reason) => {
      setConnected(false);
    });

    socketInstance.on('connect_error', (error) => {
      setConnected(false);
      const errorMsg = error.message || 'Unknown connection error';
      console.error('[SOCKET ERROR] Handshake Failed:', errorMsg);
      
      if (errorMsg.includes('Token') || errorMsg.includes('Authentication')) {
        console.warn('Authentication failed. Please verify your JWT_TOKEN or login session.');
      }
    });

    socketInstance.on('network_snapshot', (payload: NetworkSnapshotPayload) => {
      handlersRef.current.onNetworkSnapshot?.(normalizeNetworkSnapshot('network_snapshot', payload));
    });

    socketInstance.on('networks_snapshot', (payload: NetworkSnapshotPayload) => {
      handlersRef.current.onNetworkSnapshot?.(normalizeNetworkSnapshot('networks_snapshot', payload));
    });

    socketInstance.on('sensor_snapshot', (event: SensorSnapshotEvent) => {
      handlersRef.current.onSensorSnapshot?.(event);
    });

    socketInstance.on('sensor_status_update', (event: SensorStatusUpdateEvent) => {
      const sensorId = event.data.sensor_id;
      const newStatus = event.data.status;
      const oldStatus = previousSensorStatus.current[sensorId];
      
      const isTransition = oldStatus !== undefined && oldStatus !== newStatus;
      previousSensorStatus.current[sensorId] = newStatus;

      handlersRef.current.onSensorStatusUpdate?.({
        ...event,
        isTransition
      });
    });

    socketInstance.on('network_removed', (event: NetworkRemovedEvent) => {
      handlersRef.current.onNetworkRemoved?.(event);
    });

    socketInstance.on('attack_command', (event: AttackCommandEvent) => {
      handlersRef.current.onAttackCommand?.(event);
    });

    socketInstance.on('attack_command_ack', (event: AttackCommandAckEvent) => {
      handlersRef.current.onAttackCommandAck?.(event);
    });

    socketInstance.on('attack_ack', (event: AttackAckEvent) => {
      handlersRef.current.onAttackAck?.(event);
    });

    socketInstance.on('threat_event', (event: ThreatEvent) => {
      handlersRef.current.onThreatEvent?.(event);
    });

    socketInstance.on('evil_twin_suspected', (event: EvilTwinSuspectedEvent) => {
      handlersRef.current.onEvilTwinSuspected?.(event);
    });

    socketInstance.on('trusted_ap_anomaly', (event: TrustedApAnomalyEvent) => {
      handlersRef.current.onTrustedApAnomaly?.(event);
    });

    socketInstance.on('trusted_weak_encryption', (event: TrustedWeakEncryptionEvent) => {
      handlersRef.current.onTrustedWeakEncryption?.(event);
    });

    socketRef.current = socketInstance;
    setSocket(socketInstance);
  }, []);

  const disconnect = useCallback(() => {
    if (!socketRef.current) return;
    for (const eventName of SOCKET_EVENTS) socketRef.current.off(eventName);
    socketRef.current.disconnect();
    socketRef.current = null;
    setSocket(null);
    setConnected(false);
  }, []);

  const sendAttackCommand = useCallback((payload: AttackCommandEvent) => {
    if (!socketRef.current?.connected) throw new Error('Socket is not connected');
    socketRef.current.emit('attack_command', payload);
  }, []);

  useEffect(() => {
    if (autoConnect) connect();
    return () => disconnect();
  }, [autoConnect, connect, disconnect]);

  return { connect, disconnect, isConnected: connected, socket, sendAttackCommand };
}

export function useThreatEvents(onEvent?: (event: ThreatEvent) => void) {
  useSocket({ onThreatEvent: onEvent });
}

export function useSensorStatus(onEvent?: (event: SensorStatusUpdateEvent) => void) {
  useSocket({ onSensorStatusUpdate: onEvent });
}
