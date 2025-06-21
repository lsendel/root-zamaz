import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminService } from '../../services'
import { useUIStore } from '../../stores/ui-store'
import type { User, UserWithRoles } from '../../types/auth'

// Query keys
export const userKeys = {
  all: ['users'] as const,
  lists: () => [...userKeys.all, 'list'] as const,
  list: (filters: string) => [...userKeys.lists(), filters] as const,
  details: () => [...userKeys.all, 'detail'] as const,
  detail: (id: number) => [...userKeys.details(), id] as const,
}

// Get all users query
export const useUsers = () => {
  return useQuery({
    queryKey: userKeys.lists(),
    queryFn: async () => {
      const response = await adminService.getUsers()
      return response.data
    },
    staleTime: 2 * 60 * 1000, // 2 minutes
  })
}

// Get user by ID query
export const useUser = (id: number) => {

  return useQuery({
    queryKey: userKeys.detail(id),
    queryFn: async () => {
      const response = await adminService.getUserById(id)
      return response.data
    },
    enabled: !!id,
    staleTime: 5 * 60 * 1000, // 5 minutes
  })
}

// Update user mutation
export const useUpdateUser = () => {
  const queryClient = useQueryClient()
  const addNotification = useUIStore(state => state.addNotification)

  return useMutation({
    mutationFn: async ({ id, user }: { id: number; user: Partial<User> }) => {
      const response = await adminService.updateUser(id, user)
      return response.data
    },
    onMutate: async ({ id, user }) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: userKeys.detail(id) })
      await queryClient.cancelQueries({ queryKey: userKeys.lists() })

      // Snapshot previous values
      const previousUser = queryClient.getQueryData<UserWithRoles>(userKeys.detail(id))
      const previousUsers = queryClient.getQueryData<UserWithRoles[]>(userKeys.lists())

      // Optimistically update user detail
      if (previousUser) {
        queryClient.setQueryData(userKeys.detail(id), {
          ...previousUser,
          ...user
        })
      }

      // Optimistically update users list
      if (previousUsers) {
        queryClient.setQueryData(
          userKeys.lists(),
          previousUsers.map(u => u.id === id.toString() ? { ...u, ...user } : u)
        )
      }

      return { previousUser, previousUsers }
    },
    onSuccess: (updatedUser, { id }) => {
      // Update cache with server response
      queryClient.setQueryData(userKeys.detail(id), updatedUser)
      
      addNotification({
        type: 'success',
        title: 'User Updated',
        message: 'User information has been updated successfully'
      })
    },
    onError: (error: any, { id }, context) => {
      // Rollback optimistic updates
      if (context?.previousUser) {
        queryClient.setQueryData(userKeys.detail(id), context.previousUser)
      }
      if (context?.previousUsers) {
        queryClient.setQueryData(userKeys.lists(), context.previousUsers)
      }

      addNotification({
        type: 'error',
        title: 'Update Failed',
        message: error.message || 'Failed to update user'
      })
    },
    onSettled: (_, __, { id }) => {
      // Always refetch after error or success
      queryClient.invalidateQueries({ queryKey: userKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
    }
  })
}

// Delete user mutation
export const useDeleteUser = () => {
  const queryClient = useQueryClient()
  const addNotification = useUIStore(state => state.addNotification)

  return useMutation({
    mutationFn: async (id: number) => {
      const response = await adminService.deleteUser(id)
      return response.data
    },
    onMutate: async (id: number) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: userKeys.lists() })

      // Snapshot previous value
      const previousUsers = queryClient.getQueryData<UserWithRoles[]>(userKeys.lists())

      // Optimistically remove user from list
      if (previousUsers) {
        queryClient.setQueryData(
          userKeys.lists(),
          previousUsers.filter(user => user.id !== id)
        )
      }

      return { previousUsers }
    },
    onSuccess: () => {
      addNotification({
        type: 'success',
        title: 'User Deleted',
        message: 'User has been deleted successfully'
      })
    },
    onError: (error: any, id, context) => {
      // Rollback optimistic update
      if (context?.previousUsers) {
        queryClient.setQueryData(userKeys.lists(), context.previousUsers)
      }

      addNotification({
        type: 'error',
        title: 'Delete Failed',
        message: error.message || 'Failed to delete user'
      })
    },
    onSettled: () => {
      // Always refetch after error or success
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
    }
  })
}

// Assign role to user mutation
export const useAssignRole = () => {
  const queryClient = useQueryClient()
  const addNotification = useUIStore(state => state.addNotification)

  return useMutation({
    mutationFn: async ({ userId, roleId }: { userId: number; roleId: string }) => {
      const response = await adminService.assignRoleToUser(userId, roleId)
      return response.data
    },
    onSuccess: (_, { userId }) => {
      // Invalidate user data to refetch with new role
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
      
      addNotification({
        type: 'success',
        title: 'Role Assigned',
        message: 'Role has been assigned to user successfully'
      })
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: 'Assignment Failed',
        message: error.message || 'Failed to assign role'
      })
    }
  })
}

// Remove role from user mutation
export const useRemoveRole = () => {
  const queryClient = useQueryClient()
  const addNotification = useUIStore(state => state.addNotification)

  return useMutation({
    mutationFn: async ({ userId, roleId }: { userId: number; roleId: number }) => {
      const response = await adminService.removeRoleFromUser(userId, roleId)
      return response.data
    },
    onSuccess: (_, { userId }) => {
      // Invalidate user data to refetch without the role
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
      
      addNotification({
        type: 'success',
        title: 'Role Removed',
        message: 'Role has been removed from user successfully'
      })
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: 'Removal Failed',
        message: error.message || 'Failed to remove role'
      })
    }
  })
}