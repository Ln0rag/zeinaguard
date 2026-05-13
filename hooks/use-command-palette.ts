/**
 * useCommandPalette Hook - Command Palette Management
 * Handles global keyboard shortcuts and command execution
 */

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export interface Command {
  id: string;
  title: string;
  description?: string;
  category: string;
  icon?: string;
  shortcut?: string;
  action: () => void | Promise<void>;
  canExecute?: () => boolean;
}

interface UseCommandPaletteOptions {
  commands?: Command[];
  onOpen?: () => void;
  onClose?: () => void;
}

export function useCommandPalette(options: UseCommandPaletteOptions = {}) {
  const router = useRouter();
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [commands, setCommands] = useState<Command[]>(options.commands || []);

  // Initialize default commands
  useEffect(() => {
    const defaultCommands: Command[] = [
      {
        id: 'go-dashboard',
        title: 'Go to Dashboard',
        description: 'View the main security dashboard',
        category: 'Navigation',
        shortcut: 'Cmd+D',
        action: () => {
          router.push('/dashboard');
          handleClose();
        },
      },
      {
        id: 'go-threats',
        title: 'Go to Threats',
        description: 'View real-time threat feed',
        category: 'Navigation',
        shortcut: 'Cmd+T',
        action: () => {
          router.push('/threats');
          handleClose();
        },
      },
      {
        id: 'go-sensors',
        title: 'Go to Sensors',
        description: 'Manage WIPS sensors',
        category: 'Navigation',
        shortcut: 'Cmd+S',
        action: () => {
          router.push('/sensors');
          handleClose();
        },
      },
      {
        id: 'simulate-threat',
        title: 'Simulate Threat',
        description: 'Trigger a test threat for demonstration',
        category: 'Testing',
        action: async () => {
          try {
            const response = await fetch(
              `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/api/threats/demo/simulate-threat`,
              { method: 'POST' }
            );
            if (response.ok) {
              console.log('[Command] Threat simulated');
            }
            handleClose();
          } catch (error) {
            console.error('[Command] Failed to simulate threat:', error);
          }
        },
      },
      {
        id: 'refresh-data',
        title: 'Refresh Data',
        description: 'Refresh dashboard metrics',
        category: 'Actions',
        shortcut: 'Cmd+R',
        action: () => {
          window.dispatchEvent(new CustomEvent('refresh-dashboard'));
          handleClose();
        },
      },
      {
        id: 'toggle-theme',
        title: 'Toggle Theme',
        description: 'Switch between light and dark themes',
        category: 'Settings',
        action: () => {
          // Implementation for theme toggle
          const isDark = document.documentElement.classList.contains('dark');
          if (isDark) {
            document.documentElement.classList.remove('dark');
            localStorage.setItem('theme', 'light');
          } else {
            document.documentElement.classList.add('dark');
            localStorage.setItem('theme', 'dark');
          }
          handleClose();
        },
      },
      {
        id: 'focus-search',
        title: 'Focus Search',
        description: 'Focus on search input',
        category: 'Navigation',
        shortcut: 'Cmd+/',
        action: () => {
          document.getElementById('command-input')?.focus();
        },
      },
      {
        id: 'view-documentation',
        title: 'View Documentation',
        description: 'Open ZeinaGuard Pro documentation',
        category: 'Help',
        action: () => {
          window.open('/docs', '_blank');
          handleClose();
        },
      },
      {
        id: 'keyboard-shortcuts',
        title: 'Keyboard Shortcuts',
        description: 'Display all available keyboard shortcuts',
        category: 'Help',
        action: () => {
          window.dispatchEvent(new CustomEvent('show-shortcuts'));
          handleClose();
        },
      },
    ];

    setCommands([...defaultCommands, ...(options.commands || [])]);
  }, [options.commands, router]);

  // Filter commands based on search query
  const filteredCommands = searchQuery
    ? commands.filter(
        (cmd) =>
          cmd.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
          cmd.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          cmd.category.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : commands;

  const handleOpen = useCallback(() => {
    setIsOpen(true);
    setSelectedIndex(0);
    setSearchQuery('');
    options.onOpen?.();
  }, [options]);

  const handleClose = useCallback(() => {
    setIsOpen(false);
    setSearchQuery('');
    setSelectedIndex(0);
    options.onClose?.();
  }, [options]);

  const handleExecuteCommand = useCallback(
    (command: Command) => {
      if (command.canExecute && !command.canExecute()) {
        return;
      }
      command.action();
    },
    []
  );

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Cmd+K or Ctrl+K to open palette
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen((prev) => !prev);
      }

      // If palette is open
      if (isOpen) {
        // Escape to close
        if (e.key === 'Escape') {
          handleClose();
        }

        // Arrow keys to navigate
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          setSelectedIndex((prev) =>
            prev < filteredCommands.length - 1 ? prev + 1 : prev
          );
        }

        if (e.key === 'ArrowUp') {
          e.preventDefault();
          setSelectedIndex((prev) => (prev > 0 ? prev - 1 : prev));
        }

        // Enter to execute
        if (e.key === 'Enter' && filteredCommands.length > 0) {
          e.preventDefault();
          handleExecuteCommand(filteredCommands[selectedIndex]);
        }
      }

      // Direct shortcuts (when palette is closed)
      if (!isOpen) {
        // Cmd+D for dashboard
        if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'd') {
          e.preventDefault();
          router.push('/dashboard');
        }

        // Cmd+T for threats
        if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 't') {
          e.preventDefault();
          router.push('/threats');
        }

        // Cmd+S for sensors
        if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 's') {
          e.preventDefault();
          router.push('/sensors');
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, filteredCommands, selectedIndex, handleClose, handleExecuteCommand, router]);

  return {
    isOpen,
    searchQuery,
    selectedIndex,
    commands: filteredCommands,
    groupedCommands: filteredCommands.reduce(
      (acc, cmd) => {
        if (!acc[cmd.category]) {
          acc[cmd.category] = [];
        }
        acc[cmd.category].push(cmd);
        return acc;
      },
      {} as Record<string, Command[]>
    ),
    open: handleOpen,
    close: handleClose,
    setSearchQuery,
    setSelectedIndex,
    executeCommand: handleExecuteCommand,
  };
}

/**
 * Hook to listen for command palette events
 */
export function useCommandListener(eventName: string, callback: () => void) {
  useEffect(() => {
    window.addEventListener(eventName, callback);
    return () => window.removeEventListener(eventName, callback);
  }, [eventName, callback]);
}
