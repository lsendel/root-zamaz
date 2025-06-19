import { create } from 'zustand'
import { devtools } from 'zustand/middleware'

interface Notification {
  id: string
  type: 'success' | 'error' | 'warning' | 'info'
  title: string
  message?: string
  duration?: number
}

interface UIState {
  // Loading states
  isLoading: boolean
  loadingMessage: string

  // Notifications
  notifications: Notification[]

  // Modals and dialogs
  isModalOpen: boolean
  modalContent: React.ReactNode | null

  // Sidebar and navigation
  isSidebarOpen: boolean
  isMobile: boolean

  // Theme
  theme: 'light' | 'dark'

  // Actions
  setLoading: (loading: boolean, message?: string) => void
  addNotification: (notification: Omit<Notification, 'id'>) => void
  removeNotification: (id: string) => void
  clearNotifications: () => void
  openModal: (content: React.ReactNode) => void
  closeModal: () => void
  toggleSidebar: () => void
  setSidebarOpen: (open: boolean) => void
  setMobile: (mobile: boolean) => void
  setTheme: (theme: 'light' | 'dark') => void
  toggleTheme: () => void
}

export const useUIStore = create<UIState>()((
  devtools(
    (set, get) => ({
      // Initial state
      isLoading: false,
      loadingMessage: '',
      notifications: [],
      isModalOpen: false,
      modalContent: null,
      isSidebarOpen: true,
      isMobile: false,
      theme: 'light',

      // Actions
      setLoading: (loading: boolean, message = '') => {
        set({ isLoading: loading, loadingMessage: message })
      },

      addNotification: (notification) => {
        const id = Date.now().toString() + Math.random().toString(36).substr(2, 9)
        const newNotification: Notification = {
          id,
          duration: 5000, // Default 5 seconds
          ...notification
        }
        
        set((state) => ({
          notifications: [...state.notifications, newNotification]
        }))

        // Auto-remove notification after duration
        if (newNotification.duration && newNotification.duration > 0) {
          setTimeout(() => {
            get().removeNotification(id)
          }, newNotification.duration)
        }
      },

      removeNotification: (id: string) => {
        set((state) => ({
          notifications: state.notifications.filter(n => n.id !== id)
        }))
      },

      clearNotifications: () => {
        set({ notifications: [] })
      },

      openModal: (content: React.ReactNode) => {
        set({ isModalOpen: true, modalContent: content })
      },

      closeModal: () => {
        set({ isModalOpen: false, modalContent: null })
      },

      toggleSidebar: () => {
        set((state) => ({ isSidebarOpen: !state.isSidebarOpen }))
      },

      setSidebarOpen: (open: boolean) => {
        set({ isSidebarOpen: open })
      },

      setMobile: (mobile: boolean) => {
        set({ isMobile: mobile })
        // Auto-close sidebar on mobile
        if (mobile) {
          set({ isSidebarOpen: false })
        }
      },

      setTheme: (theme: 'light' | 'dark') => {
        set({ theme })
        // Update document class for CSS theming
        document.documentElement.className = theme
        localStorage.setItem('theme', theme)
      },

      toggleTheme: () => {
        const { theme } = get()
        const newTheme = theme === 'light' ? 'dark' : 'light'
        get().setTheme(newTheme)
      }
    }),
    {
      name: 'ui-store'
    }
  )
))