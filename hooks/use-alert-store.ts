import { create } from 'zustand';

export interface AlertNotification {
  id: string;
  type: string;
  title: string;
  time: string;
  bssid: string;
  ssid?: string;
  channel?: number | null;
  signal?: number | null;
  manufacturer?: string | null;
  sensor_id?: string;
  hostname?: string;
  interface?: string;
  uptime?: number;
  purge_count?: number;
  purge_type?: string;
  report_name?: string;
  download_url?: string;
}

interface AlertStore {
  notifications: AlertNotification[];
  hasUnread: boolean;
  addNotification: (notification: Omit<AlertNotification, 'id' | 'time'>) => void;
  markRead: () => void;
  clear: () => void;
}

const MAX_NOTIFICATIONS = 50;

export const useAlertStore = create<AlertStore>((set) => ({
  notifications: [],
  hasUnread: false,
  addNotification: (notification) =>
    set((state) => ({
      notifications: [
        {
          ...notification,
          id: Math.random().toString(36).slice(2, 11),
          time: new Date().toLocaleTimeString(),
        },
        ...state.notifications,
      ].slice(0, MAX_NOTIFICATIONS),
      hasUnread: true,
    })),
  markRead: () => set({ hasUnread: false }),
  clear: () => set({ notifications: [], hasUnread: false }),
}));
