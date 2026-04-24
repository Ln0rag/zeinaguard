'use client';

import { ReactNode } from 'react';
import { Sidebar } from './sidebar';
import { CommandPalette } from '../command-palette';
import { NotificationCenter } from '../notifications/notification-center';

interface AppLayoutProps {
  children: ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className="flex min-h-screen bg-slate-900">
      <Sidebar />
      <main className="flex-1 ml-64 bg-slate-900">
        {/* Top Navbar */}
        <div className="sticky top-0 bg-slate-900 border-b border-slate-800 px-8 py-4 flex justify-end items-center z-40">
          <NotificationCenter />
        </div>
        
        {/* Main Content */}
        <div>
          {children}
        </div>
      </main>
      <CommandPalette />
    </div>
  );
}
