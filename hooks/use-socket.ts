'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';

// تعريف واجهة بيانات الشبكة الموحدة (Interface)
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

// تعريف حدث حذف الشبكة
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
}

export interface AttackCommandAckEvent {
  status: 'ok' | 'error';
  sensor_id?: number;
  bssid?: string;
  channel?: number | null;
  message?: string | null;
  timestamp: string;
}

interface UseSocketOptions {
  onNetworkSnapshot?: (event: NetworkSnapshotEvent) => void;
  onSensorSnapshot?: (event: SensorSnapshotEvent) => void;
  onSensorStatusUpdate?: (event: SensorStatusUpdateEvent) => void;
  onNetworkRemoved?: (event: NetworkRemovedEvent) => void;
  onThreatDetected?: (event: LiveNetworkEvent) => void;
  onAttackCommand?: (event: AttackCommandEvent) => void;
  onAttackCommandAck?: (event: AttackCommandAckEvent) => void;
  onAttackAck?: (event: AttackAckEvent) => void;
  onThreatEvent?: (event: ThreatEvent) => void;
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
] as const;

function resolveSocketUrl(): string {
  return (
    process.env.NEXT_PUBLIC_SOCKET_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    process.env.NEXT_PUBLIC_BACKEND_URL ||
    'http://localhost:5000'
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

// الدالة الجوهرية لضبط بيانات كل شبكة
function normalizeNetworkItem(item: unknown): LiveNetworkEvent {
  const network = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>;
  const lastSeen = normalizeLastSeen(network.last_seen ?? network.timestamp);

  return {
    sensor_id: Number(network.sensor_id || 0),
    ssid: String(network.ssid || 'Hidden').trim() || 'Hidden',
    bssid: String(network.bssid || '').trim().toUpperCase(),
    signal: typeof network.signal === 'number' ? network.signal : network.signal == null ? null : Number(network.signal),
    channel: typeof network.channel === 'number' ? network.channel : network.channel == null ? null : Number(network.channel),
    frequency: typeof network.frequency === 'number' ? network.frequency : network.frequency == null ? null : Number(network.frequency),
    classification: normalizeClassification(network.classification),
    
    // تأمين ظهور السكور والأسباب والحصانة لشبكتك
    score: Number(network.score || 0),
    is_trusted: Boolean(network.is_trusted || false),
    reasons: Array.isArray(network.reasons) ? network.reasons : [],
    
    last_seen: lastSeen,
    timestamp: typeof network.timestamp === 'string' ? network.timestamp : lastSeen,
    manufacturer: network.manufacturer == null ? null : String(network.manufacturer),
    clients: normalizeClients(network.clients),
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
    onThreatDetected,
    onAttackCommand,
    onAttackCommandAck,
    onAttackAck,
    onThreatEvent,
    autoConnect = true,
  } = options;

  const socketRef = useRef<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const handlersRef = useRef({
    onNetworkSnapshot,
    onSensorSnapshot,
    onSensorStatusUpdate,
    onNetworkRemoved,
    onThreatDetected,
    onAttackCommand,
    onAttackCommandAck,
    onAttackAck,
    onThreatEvent,
  });

  useEffect(() => {
    handlersRef.current = {
      onNetworkSnapshot,
      onSensorSnapshot,
      onSensorStatusUpdate,
      onNetworkRemoved,
      onThreatDetected,
      onAttackCommand,
      onAttackCommandAck,
      onAttackAck,
      onThreatEvent,
    };
  }, [onAttackAck, onAttackCommand, onAttackCommandAck, onNetworkRemoved, onNetworkSnapshot, onSensorSnapshot, onSensorStatusUpdate, onThreatDetected, onThreatEvent]);

  const connect = useCallback(() => {
    if (socketRef.current) return;

    const socketUrl = resolveSocketUrl();
    const socket = io(socketUrl, {
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity,
      timeout: 10000,
      transports: ['websocket', 'polling'],
    });

    socket.on('connect', () => {
      setConnected(true);
      console.log('[SOCKET CONNECTED]', { socketUrl, id: socket.id });
    });

    socket.on('disconnect', (reason) => {
      setConnected(false);
      console.log('[SOCKET DISCONNECTED]', { reason });
    });

    socket.on('connect_error', (error) => {
      setConnected(false);
      console.error('[SOCKET ERROR]', error);
    });

    socket.on('network_snapshot', (payload: NetworkSnapshotPayload) => {
      handlersRef.current.onNetworkSnapshot?.(normalizeNetworkSnapshot('network_snapshot', payload));
    });

    socket.on('networks_snapshot', (payload: NetworkSnapshotPayload) => {
      handlersRef.current.onNetworkSnapshot?.(normalizeNetworkSnapshot('networks_snapshot', payload));
    });

    socket.on('sensor_snapshot', (event: SensorSnapshotEvent) => {
      handlersRef.current.onSensorSnapshot?.(event);
    });

    socket.on('sensor_status_update', (event: SensorStatusUpdateEvent) => {
      handlersRef.current.onSensorStatusUpdate?.(event);
    });

    socket.on('network_removed', (event: NetworkRemovedEvent) => {
      handlersRef.current.onNetworkRemoved?.(event);
    });

    socket.on('threat_detected', (event: any) => {
      // استخدام دالة التنظيم لضمان وصول السكور والأسباب
      handlersRef.current.onThreatDetected?.(normalizeNetworkItem(event));
    });

    socket.on('attack_command', (event: AttackCommandEvent) => {
      handlersRef.current.onAttackCommand?.(event);
    });

    socket.on('attack_command_ack', (event: AttackCommandAckEvent) => {
      handlersRef.current.onAttackCommandAck?.(event);
    });

    socket.on('attack_ack', (event: AttackAckEvent) => {
      handlersRef.current.onAttackAck?.(event);
    });

    socket.on('threat_event', (event: ThreatEvent) => {
      handlersRef.current.onThreatEvent?.(event);
    });

    socketRef.current = socket;
  }, []);

  const disconnect = useCallback(() => {
    if (!socketRef.current) return;
    for (const eventName of SOCKET_EVENTS) socketRef.current.off(eventName);
    socketRef.current.disconnect();
    socketRef.current = null;
    setConnected(false);
  }, []);

  const isConnected = useCallback(() => connected, [connected]);
  const getSocket = useCallback(() => socketRef.current, []);

  const sendAttackCommand = useCallback((payload: AttackCommandEvent) => {
    if (!socketRef.current?.connected) throw new Error('Socket is not connected');
    socketRef.current.emit('attack_command', payload);
  }, []);

  useEffect(() => {
    if (autoConnect) connect();
    return () => disconnect();
  }, [autoConnect, connect, disconnect]);

  return { connect, disconnect, isConnected, getSocket, sendAttackCommand };
}

export function useThreatEvents(onEvent?: (event: ThreatEvent) => void) {
  useSocket({ onThreatEvent: onEvent });
}

export function useSensorStatus(onEvent?: (event: SensorStatusUpdateEvent) => void) {
  useSocket({ onSensorStatusUpdate: onEvent });
}