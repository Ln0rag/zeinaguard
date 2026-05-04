/**
 * useAuth Hook - Authentication state and methods
 * Manages user authentication for the entire application
 */

import { useEffect } from 'react'; // Added useEffect to solve Infinite Loop issue
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import {
  authAPI,
  User,
  getAccessToken,
  setAccessToken,
  clearAccessToken,
  getStoredUser,
  setStoredUser,
} from '@/lib/api';

/**
 * Auth state interface
 */
interface AuthState {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  error: string | null;
  isAuthenticated: boolean;

  // Actions
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<void>;
  clearError: () => void;
  initializeAuth: () => void;
}

/**
 * Create Zustand store for authentication
 */
const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isLoading: false,
      error: null,
      isAuthenticated: false,

      /**
       * Login user
       */
      login: async (username: string, password: string) => {
        set({ isLoading: true, error: null });

        try {
          const response = await authAPI.login(username, password);

          set({
            user: response.user,
            token: response.access_token,
            isAuthenticated: true,
            isLoading: false,
          });
        } catch (error) {
          const errorMessage =
            error instanceof Error ? error.message : 'Login failed';

          set({
            error: errorMessage,
            isLoading: false,
            isAuthenticated: false,
          });

          throw error;
        }
      },

      /**
       * Logout user
       */
      logout: async () => {
        set({ isLoading: true });

        try {
          await authAPI.logout();
        } catch (error) {
          console.error('Logout error:', error);
        }

        set({
          user: null,
          token: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
        });
      },

      /**
       * Refresh authentication token
       */
      refreshToken: async () => {
        try {
          const response = await authAPI.refresh();

          set({
            user: response.user,
            token: response.access_token,
            isAuthenticated: true,
          });
        } catch (error) {
          set({
            user: null,
            token: null,
            isAuthenticated: false,
            error: 'Token refresh failed',
          });

          throw error;
        }
      },

      /**
       * Clear error message
       */
      clearError: () => {
        set({ error: null });
      },

      /**
       * Initialize auth from stored values
       */
      initializeAuth: () => {
        const token = getAccessToken();
        const user = getStoredUser();

        if (token && user) {
          set({
            token,
            user,
            isAuthenticated: true,
          });
        }
      },
    }),
    {
      name: 'auth-store',
      // Only persist these fields
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);

/**
 * Custom hook to use auth state
 */
export function useAuth(): AuthState {
  return useAuthStore((state) => state);
}

/**
 * Custom hook for non-suspense auth initialization
 * Fixed error by moving initializeAuth to useEffect
 */
export function useAuthInit() {
  const store = useAuthStore();

  useEffect(() => {
    // Run update after render to prevent Side Effects conflicts with Sidebar
    if (typeof window !== 'undefined') {
      store.initializeAuth();
    }
  }, []); // Empty array ensures single run on page load

  return store;
}

/**
 * Get auth state (for server components if needed)
 */
export function getAuthState(): Partial<AuthState> {
  const state = useAuthStore.getState();
  return {
    user: state.user,
    token: state.token,
    isAuthenticated: state.isAuthenticated,
  };
}

export { useAuthStore };