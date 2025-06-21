import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { authService } from "../../services";
import { useAuthStore } from "../../stores/auth-store";
import { useUIStore } from "../../stores/ui-store";

// Query keys
export const authKeys = {
  all: ["auth"] as const,
  user: () => [...authKeys.all, "user"] as const,
  profile: () => [...authKeys.all, "profile"] as const,
};

// Login mutation
export const useLogin = () => {
  const setUser = useAuthStore((state) => state.setUser);
  const setToken = useAuthStore((state) => state.setToken);
  const addNotification = useUIStore((state) => state.addNotification);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (credentials: any) => {
      const response = await authService.login(credentials);
      return response;
    },
    onSuccess: (response) => {
      const { user, token } = response.data;
      setUser(user);
      setToken(token);

      // Cache user data
      queryClient.setQueryData(authKeys.user(), user);

      addNotification({
        type: "success",
        title: "Login Successful",
        message: `Welcome back, ${user.first_name}!`,
      });
    },
    onError: (error: any) => {
      addNotification({
        type: "error",
        title: "Login Failed",
        message: error.message || "Invalid credentials",
      });
    },
  });
};

// Register mutation
export const useRegister = () => {
  const addNotification = useUIStore((state) => state.addNotification);

  return useMutation({
    mutationFn: async (credentials: any) => {
      const response = await authService.register(credentials);
      return response;
    },
    onSuccess: () => {
      addNotification({
        type: "success",
        title: "Registration Successful",
        message: "Please check your email to verify your account",
      });
    },
    onError: (error: any) => {
      addNotification({
        type: "error",
        title: "Registration Failed",
        message: error.message || "Registration failed",
      });
    },
  });
};

// Logout mutation
export const useLogout = () => {
  const logout = useAuthStore((state) => state.logout);
  const addNotification = useUIStore((state) => state.addNotification);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      const response = await authService.logout();
      return response;
    },
    onSuccess: () => {
      logout();
      queryClient.clear(); // Clear all cached data

      addNotification({
        type: "info",
        title: "Logged Out",
        message: "You have been successfully logged out",
      });
    },
    onError: () => {
      // Even if API call fails, still logout locally
      logout();
      queryClient.clear();
    },
  });
};

// Get current user query
export const useCurrentUser = () => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const token = useAuthStore((state) => state.token);

  return useQuery({
    queryKey: authKeys.user(),
    queryFn: async () => {
      const response = await authService.getCurrentUser();
      return response.data;
    },
    enabled: isAuthenticated && !!token,
    staleTime: 5 * 60 * 1000, // 5 minutes
    retry: (failureCount, error: any) => {
      // Don't retry on auth errors
      if (error.code === "UNAUTHORIZED") {
        return false;
      }
      return failureCount < 3;
    },
  });
};

// Refresh token mutation
export const useRefreshToken = () => {
  const setUser = useAuthStore((state) => state.setUser);
  const setToken = useAuthStore((state) => state.setToken);
  const logout = useAuthStore((state) => state.logout);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      const response = await authService.refreshToken();
      return response;
    },
    onSuccess: (response) => {
      const { user, token } = response.data;
      setUser(user);
      setToken(token);

      // Update cached user data
      queryClient.setQueryData(authKeys.user(), user);
    },
    onError: () => {
      // If refresh fails, logout user
      logout();
      queryClient.clear();
    },
  });
};
