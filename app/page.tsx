'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    router.replace('/dashboard');
  }, [router]);

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-b from-slate-900 to-slate-950">
      <div className="text-center">
        <h1 className="text-3xl font-bold text-white mb-2">ZeinaGuard Pro</h1>
        <p className="text-slate-500 mb-4">Rouge Access Points Detection and Prevention System</p>
        <p className="text-slate-400">Redirecting...</p>
      </div>
    </div>
  );
}
