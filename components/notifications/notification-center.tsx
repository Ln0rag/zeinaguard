'use client';

import { useState } from 'react';
import { X, Bell, Trash2, CheckCheck } from 'lucide-react';
import { useNotifications } from '@/context/notification-context';
import { notificationService } from '@/lib/notification-service';
import { formatDistanceToNow } from 'date-fns';

export function NotificationCenter() {
  const [isOpen, setIsOpen] = useState(false);
  const { notifications, unreadCount, markAsRead, removeNotification, markAllAsRead, clearAll } = useNotifications();

  const handleTestNotification = () => {
    notificationService.notifyWithPermission({
      title: '🧪 Test Notification',
      message: 'This is a test notification from ZeinaGuard',
      type: 'info',
    });
  };

  const getTypeStyles = (type: string) => {
    const styles = {
      info: 'border-blue-500/30 bg-blue-900/20',
      warning: 'border-yellow-500/30 bg-yellow-900/20',
      critical: 'border-red-500/30 bg-red-900/20',
    };
    return styles[type as keyof typeof styles] || styles.info;
  };

  const getTypeIcon = (type: string) => {
    const icons = {
      info: '🔵',
      warning: '🟡',
      critical: '🔴',
    };
    return icons[type as keyof typeof icons] || '🔵';
  };

  const typeColors = {
    info: 'text-blue-400',
    warning: 'text-yellow-400',
    critical: 'text-red-400',
  };

  return (
    <div className="relative">
      {/* Bell Icon Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        title="Notifications"
        className="relative p-2 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute top-0 right-0 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center font-bold">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown Panel */}
      {isOpen && (
        <div className="absolute right-0 top-12 w-96 bg-slate-800 border border-slate-700 rounded-lg shadow-lg z-50">
          {/* Header */}
          <div className="p-4 border-b border-slate-700 flex items-center justify-between">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Bell className="w-4 h-4" />
              Notifications
              {unreadCount > 0 && (
                <span className="text-xs bg-red-600 text-white px-2 py-0.5 rounded-full">
                  {unreadCount} new
                </span>
              )}
            </h3>
            <button
              onClick={() => setIsOpen(false)}
              className="text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Notifications List */}
          <div className="max-h-96 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="p-8 text-center text-slate-400">
                <Bell className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No notifications yet</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-700">
                {notifications.map((notif) => (
                  <div
                    key={notif.id}
                    className={`p-4 border-l-4 ${getTypeStyles(notif.type)} transition-colors hover:bg-slate-700/50 ${
                      !notif.read ? 'bg-slate-700/30' : ''
                    }`}
                    onClick={() => markAsRead(notif.id)}
                  >
                    <div className="flex gap-3">
                      {/* Icon */}
                      <div className="text-xl flex-shrink-0">{getTypeIcon(notif.type)}</div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <h4 className={`font-semibold text-white ${typeColors[notif.type as keyof typeof typeColors]}`}>
                          {notif.title}
                        </h4>
                        <p className="text-sm text-slate-300 mt-1 break-words">{notif.message}</p>
                        <p className="text-xs text-slate-500 mt-2">
                          {formatDistanceToNow(notif.timestamp, { addSuffix: true })}
                        </p>
                      </div>

                      {/* Unread Indicator */}
                      {!notif.read && <div className="w-2 h-2 bg-red-500 rounded-full flex-shrink-0 mt-1" />}

                      {/* Delete Button */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          removeNotification(notif.id);
                        }}
                        className="text-slate-400 hover:text-red-400 transition-colors flex-shrink-0"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer Actions */}
          {notifications.length > 0 && (
            <div className="p-4 border-t border-slate-700 space-y-2">
              <button
                onClick={handleTestNotification}
                className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
              >
                <Bell className="w-4 h-4" />
                Test Notification
              </button>
              <div className="flex gap-2">
                <button
                  onClick={markAllAsRead}
                  className="flex-1 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-sm transition-colors flex items-center justify-center gap-1"
                >
                  <CheckCheck className="w-3 h-3" />
                  Mark All Read
                </button>
                <button
                  onClick={clearAll}
                  className="flex-1 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-sm transition-colors flex items-center justify-center gap-1"
                >
                  <Trash2 className="w-3 h-3" />
                  Clear All
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Overlay to close dropdown */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => setIsOpen(false)}
        />
      )}
    </div>
  );
}
