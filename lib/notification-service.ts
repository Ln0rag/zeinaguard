/**
 * Browser Notifications Service
 * Handles requesting permissions and triggering native browser notifications
 */

export type NotificationType = 'info' | 'warning' | 'critical';

export interface NotificationPayload {
  title: string;
  message: string;
  type: NotificationType;
  icon?: string;
  tag?: string;
}

class NotificationService {
  private isSupported: boolean;
  private permission: NotificationPermission = 'default';

  constructor() {
    this.isSupported = typeof window !== 'undefined' && 'Notification' in window;
    if (this.isSupported) {
      this.permission = Notification.permission;
    }
  }

  /**
   * Request permission from user for browser notifications
   */
  async requestPermission(): Promise<boolean> {
    if (!this.isSupported) {
      console.warn('Browser notifications not supported');
      return false;
    }

    if (this.permission === 'granted') {
      return true;
    }

    if (this.permission === 'denied') {
      return false;
    }

    try {
      const result = await Notification.requestPermission();
      this.permission = result;
      return result === 'granted';
    } catch (error) {
      console.error('Error requesting notification permission:', error);
      return false;
    }
  }

  /**
   * Check if notifications are currently enabled
   */
  isEnabled(): boolean {
    return this.isSupported && this.permission === 'granted';
  }

  /**
   * Send a browser notification
   */
  async notify(payload: NotificationPayload): Promise<void> {
    if (!this.isEnabled()) {
      console.warn('Notifications not enabled. Permission:', this.permission);
      return;
    }

    try {
      // Determine icon based on notification type
      const iconMap: Record<NotificationType, string> = {
        info: '🔵',
        warning: '🟡',
        critical: '🔴',
      };

      const notification = new Notification(payload.title, {
        body: payload.message,
        icon: payload.icon || iconMap[payload.type],
        tag: payload.tag || `notification-${Date.now()}`,
        badge: '/icon-192x192.png',
        requireInteraction: payload.type === 'critical', // Keep critical alerts until user interacts
      });

      // Log notification sent
      console.log(`📬 Browser notification sent: ${payload.title}`);

      // Auto-close non-critical notifications after 6 seconds
      if (payload.type !== 'critical') {
        setTimeout(() => notification.close(), 6000);
      }

      // Handle click on notification
      notification.addEventListener('click', () => {
        window.focus();
        notification.close();
      });
    } catch (error) {
      console.error('Error sending notification:', error);
    }
  }

  /**
   * Send notification with auto-request permission if needed
   */
  async notifyWithPermission(payload: NotificationPayload): Promise<void> {
    if (!this.isEnabled()) {
      const granted = await this.requestPermission();
      if (!granted) {
        console.warn('User denied notification permission');
        return;
      }
    }

    await this.notify(payload);
  }
}

export const notificationService = new NotificationService();
