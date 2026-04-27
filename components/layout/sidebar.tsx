'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  AlertTriangle,
  Wifi,
  Bell,
  BarChart3,
  Settings,
  Network,
} from 'lucide-react';

export function Sidebar() {
  const pathname = usePathname();

  const menuItems = [
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/threats', label: 'Threats', icon: AlertTriangle },
    { href: '/sensors', label: 'Sensors', icon: Wifi },
    { href: '/incidents', label: 'Incidents', icon: BarChart3 },
  ];

  return (
    <aside className="fixed left-0 top-0 h-screen w-16 bg-slate-900 border-r border-slate-800 flex flex-col z-50">
      
      {/* Navigation */}
      <nav className="flex-1 p-2 space-y-2">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center justify-center px-3 py-3 rounded-lg transition-colors relative ${
                isActive
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
              title={item.label}
            >
              <Icon className="w-5 h-5 flex-shrink-0" />
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
