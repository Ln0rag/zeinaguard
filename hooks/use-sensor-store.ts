import { create } from 'zustand';

interface SensorStore {
  logs: Record<number, string[]>;
  addLog: (sensorId: number, message: string) => void;
}

export const useSensorStore = create<SensorStore>((set) => ({
  logs: {},
  addLog: (sensorId, message) => set((state) => {
    const prevLogs = state.logs[sensorId] || [];
    
    if (prevLogs.length > 0 && prevLogs[prevLogs.length - 1] === message) {
      return state;
    }
    
    return {
      logs: {
        ...state.logs,
        [sensorId]: [...prevLogs, message].slice(-1000)
      }
    };
  })
}));