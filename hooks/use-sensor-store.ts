import { create } from 'zustand';

interface SensorStore {
  logs: Record<number, string[]>;
  addLog: (sensorId: number, message: string) => void;
}

export const useSensorStore = create<SensorStore>((set) => ({
  logs: {},
  addLog: (sensorId, message) => set((state) => {
    const prevLogs = state.logs[sensorId] || [];
    
    // منع تكرار نفس الرسالة ورا بعض
    if (prevLogs.length > 0 && prevLogs[prevLogs.length - 1] === message) {
      return state;
    }
    
    // إضافة الرسالة والاحتفاظ بآخر 1000 رسالة فقط لحماية الرامات
    return {
      logs: {
        ...state.logs,
        [sensorId]: [...prevLogs, message].slice(-1000)
      }
    };
  })
}));