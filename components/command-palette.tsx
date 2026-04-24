'use client';

import { useEffect, useRef } from 'react';
import { useCommandPalette } from '@/hooks/use-command-palette';
import { Search, Command as CommandIcon, AlertTriangle, Shield, Zap } from 'lucide-react';

export function CommandPalette() {
  const {
    isOpen,
    searchQuery,
    selectedIndex,
    groupedCommands,
    close,
    setSearchQuery,
    executeCommand,
  } = useCommandPalette();

  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        inputRef.current?.focus();
      }, 0);
    }
  }, [isOpen]);

  const getCategoryColor = (category: string) => {
    switch (category.toLowerCase()) {
      case 'navigation':
        return 'bg-blue-900 text-blue-100';
      case 'testing':
        return 'bg-orange-900 text-orange-100';
      case 'actions':
        return 'bg-purple-900 text-purple-100';
      case 'settings':
        return 'bg-slate-700 text-slate-100';
      default:
        return 'bg-slate-700 text-slate-100';
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          close();
        }
      }}
    >
      <div className="bg-slate-800 rounded-lg shadow-lg border border-slate-700 w-full max-w-lg max-h-96 flex flex-col">
        {/* Header */}
        <div className="border-b border-slate-700 px-4 pt-4 pb-3">
          <h2 className="text-lg font-semibold text-white">Command Palette</h2>
          <p className="text-slate-400 text-xs mt-1">
            Type to search, use arrow keys to navigate, press Enter to execute
          </p>
        </div>

        {/* Search Input */}
        <div className="flex items-center gap-2 border-b border-slate-700 px-3 py-2">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            ref={inputRef}
            id="command-input"
            type="text"
            placeholder="Search commands..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="flex-1 bg-transparent outline-none text-white placeholder-slate-400 text-sm"
            autoComplete="off"
            spellCheck="false"
          />
          <kbd className="text-xs text-slate-400 bg-slate-700 px-2 py-1 rounded">
            ESC
          </kbd>
        </div>

        {/* Command List */}
        <div className="flex-1 overflow-y-auto">
          {Object.keys(groupedCommands).length === 0 ? (
            <div className="px-4 py-8 text-center text-slate-400">
              <p className="text-sm">No commands found</p>
            </div>
          ) : (
            <div className="space-y-1 p-2">
              {Object.entries(groupedCommands).map(([category, commands]) => (
                <div key={category}>
                  <div className="px-2 py-1.5 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    {category}
                  </div>
                  <div className="space-y-0.5">
                    {commands.map((command) => (
                      <button
                        key={command.id}
                        onClick={() => {
                          executeCommand(command);
                          close();
                        }}
                        className={`w-full text-left px-3 py-2 rounded text-sm transition-colors ${
                          commands.indexOf(command) === selectedIndex
                            ? 'bg-slate-700 text-white'
                            : 'text-slate-300 hover:bg-slate-700 hover:text-white'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex-1">
                            <p className="font-medium">{command.title}</p>
                            {command.description && (
                              <p className="text-xs text-slate-400 mt-0.5">
                                {command.description}
                              </p>
                            )}
                          </div>
                          {command.shortcut && (
                            <kbd
                              className={`text-xs px-2 py-1 rounded whitespace-nowrap ml-2 ${getCategoryColor(
                                category
                              )}`}
                            >
                              {command.shortcut}
                            </kbd>
                          )}
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-slate-700 bg-slate-900 px-4 py-3 text-xs text-slate-400 flex justify-between items-center">
          <div>
            Press <kbd className="text-slate-300 bg-slate-700 px-1.5 py-0.5 rounded text-xs">
              ↑↓
            </kbd>
            {' '}to navigate, <kbd className="text-slate-300 bg-slate-700 px-1.5 py-0.5 rounded text-xs">
              ↵
            </kbd>
            {' '}to execute
          </div>
          <span className="bg-slate-700 text-slate-300 px-2 py-1 rounded">
            {Object.values(groupedCommands).reduce((sum, cmds) => sum + cmds.length, 0)} commands
          </span>
        </div>
      </div>
    </div>
  );
}

/**
 * Provider component to wrap your app with command palette
 */
export function CommandPaletteProvider({ children }: { children: React.ReactNode }) {
  return (
    <>
      {children}
      <CommandPalette />
    </>
  );
}
