'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useAuth } from '@/hooks/use-auth';

export function LoginForm() {
  const router = useRouter();
  const { login, isLoading, error, clearError } = useAuth();
  
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin123');
  const [localError, setLocalError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    clearError();

    if (!username || !password) {
      setLocalError('Please enter both username and password');
      return;
    }

    try {
      await login(username, password);
      // Redirect to dashboard on successful login
      router.push('/dashboard');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed';
      setLocalError(errorMessage);
    }
  };

  const displayError = localError || error;

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex flex-col gap-2 text-center">
        <h1 className="text-2xl font-bold tracking-tight">
          ZeinaGuard Pro
        </h1>
        <p className="text-sm text-muted-foreground">
          Wireless Intrusion Prevention System
        </p>
      </div>

      {/* Error Alert */}
      {displayError && (
        <Alert variant="destructive">
          <AlertDescription>{displayError}</AlertDescription>
        </Alert>
      )}

      {/* Login Form */}
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {/* Username Field */}
        <div className="flex flex-col gap-2">
          <Label htmlFor="username">Username</Label>
          <Input
            id="username"
            type="text"
            placeholder="admin"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={isLoading}
            autoComplete="username"
            required
          />
        </div>

        {/* Password Field */}
        <div className="flex flex-col gap-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            placeholder="••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={isLoading}
            autoComplete="current-password"
            required
          />
        </div>

        {/* Submit Button */}
        <Button 
          type="submit" 
          className="w-full"
          disabled={isLoading}
        >
          {isLoading ? 'Logging in...' : 'Login'}
        </Button>
      </form>

      {/* Demo Credentials */}
      <div className="flex flex-col gap-2 pt-4 border-t">
        <p className="text-xs text-muted-foreground font-semibold">
          Demo Credentials
        </p>
        <div className="space-y-1 text-xs">
          <p>
            <span className="font-semibold">Admin:</span> admin / admin123
          </p>
          <p>
            <span className="font-semibold">Analyst:</span> analyst / analyst123
          </p>
        </div>
      </div>

      {/* API Status Info */}
      <div className="flex flex-col gap-1 pt-4 border-t">
        <p className="text-xs text-muted-foreground">
          Make sure Flask backend is running:
        </p>
        <code className="text-xs bg-muted p-2 rounded">
          http://localhost:5000
        </code>
      </div>
    </div>
  );
}
