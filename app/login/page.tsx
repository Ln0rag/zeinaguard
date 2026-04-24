import { LoginForm } from '@/components/auth/login-form';

export const metadata = {
  title: 'Login - ZeinaGuard Pro',
  description: 'Login to ZeinaGuard Pro Wireless Intrusion Prevention System',
};

export default function LoginPage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Login Card */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-8">
          <LoginForm />
        </div>

        {/* Footer */}
        <div className="mt-8 text-center text-sm text-slate-400">
          <p>
            ZeinaGuard Pro - Enterprise Wireless Intrusion Prevention System
          </p>
          <p className="mt-2 text-xs text-slate-500">
            Phase 1: JWT Authentication
          </p>
        </div>
      </div>
    </div>
  );
}
