/**
 * Demo hook showing how to use the notification system
 * Import this in any component to trigger notifications
 */

import { useNotifications } from '@/context/notification-context';
import { notificationService } from '@/lib/notification-service';
import { useEffect } from 'react';

export function useNotificationDemo() {
  const { addNotification } = useNotifications();

  // Example: Simulate a sensor going offline (critical alert)
  const simulateSensorOffline = async () => {
    const title = '🚨 Sensor Offline';
    const message = 'Raspberry Pi 1 (Office Floor) has gone offline';
    
    // Add to notification center
    addNotification(title, message, 'critical');
    
    // Send browser notification
    await notificationService.notifyWithPermission({
      title,
      message,
      type: 'critical',
    });
  };

  // Example: Rogue AP detected
  const simulateRogueAPDetected = async () => {
    const title = 'Rogue AP Detected';
    const message = 'Unknown access point detected with suspicious beacon pattern - Immediate action required!';
    
    addNotification(title, message, 'critical');
    
    await notificationService.notifyWithPermission({
      title,
      message,
      type: 'critical',
    });
  };

  // Example: System update available
  const simulateSystemUpdate = async () => {
    const title = 'System Update Available';
    const message = 'ZeinaGuard Pro v1.2.3 update is available. Restart to apply.';
    
    addNotification(title, message, 'info');
    
    await notificationService.notifyWithPermission({
      title,
      message,
      type: 'info',
    });
  };

  // Example: High threat detected
  const simulateHighThreat = async () => {
    const title = 'High Threat Detected';
    const message = 'De-authentication attack detected on Corporate-WiFi network';
    
    addNotification(title, message, 'warning');
    
    await notificationService.notifyWithPermission({
      title,
      message,
      type: 'warning',
    });
  };

  return {
    simulateSensorOffline,
    simulateRogueAPDetected,
    simulateSystemUpdate,
    simulateHighThreat,
  };
}
