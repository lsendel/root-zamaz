import React, { Suspense, lazy } from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { QueryProvider } from './providers/query-provider'
import { ErrorBoundary } from './components/error-boundary'
import { Notifications } from './components/notifications'
import ProtectedRoute from './components/ProtectedRoute'
import './App.css'

// Lazy load pages for code splitting
const LoginPage = lazy(() => import('./pages/LoginPage'))
const DashboardPage = lazy(() => import('./pages/DashboardPage'))

// Loading component
const PageLoader: React.FC = () => (
  <div className="page-loader">
    <div className="page-loader__spinner"></div>
    <p>Loading...</p>
  </div>
)

function App() {
  return (
    <ErrorBoundary>
      <QueryProvider>
        <Router>
          <div className="app">
            <Suspense fallback={<PageLoader />}>
              <Routes>
                <Route path="/login" element={<LoginPage />} />
                <Route 
                  path="/dashboard" 
                  element={
                    <ProtectedRoute>
                      <DashboardPage />
                    </ProtectedRoute>
                  } 
                />
                <Route path="/" element={<LoginPage />} />
              </Routes>
            </Suspense>
            <Notifications />
          </div>
        </Router>
      </QueryProvider>
    </ErrorBoundary>
  )
}

export default App