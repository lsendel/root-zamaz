import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/auth-store'
import { useLogin } from '../hooks/api/use-auth'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  
  const isAuthenticated = useAuthStore(state => state.isAuthenticated)
  const isLoading = useAuthStore(state => state.isLoading)
  const error = useAuthStore(state => state.error)
  const clearError = useAuthStore(state => state.clearError)
  
  const loginMutation = useLogin()
  const navigate = useNavigate()

  useEffect(() => {
    // Set page title for login page
    document.title = 'Login - MVP Zero Trust Auth'
    
    if (isAuthenticated) {
      navigate('/dashboard')
    }
  }, [isAuthenticated, navigate])

  useEffect(() => {
    // Clear error when component mounts or when inputs change
    if (error) {
      clearError()
    }
  }, [email, password, clearError, error])

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()

    try {
      await loginMutation.mutateAsync({ username: email, password })
      navigate('/dashboard')
    } catch (error) {
      // Error is handled by the mutation
    }
  }

  if (isLoading) {
    return (
      <div className="app">
        <div>Loading...</div>
      </div>
    )
  }

  return (
    <div className="app">
      <main className="main-content">
        <h1>MVP Zero Trust Authentication</h1>
        <p>Secure access through device attestation and identity verification</p>
        
        <form onSubmit={handleSubmit} className="login-form">
          <h2>Sign In</h2>
          
          {error && (
            <div className="error">
              {error}
            </div>
          )}
          
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              name="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loginMutation.isPending}
              placeholder="Enter your email"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loginMutation.isPending}
              placeholder="Enter your password"
            />
          </div>
          
          <button 
            type="submit" 
            disabled={loginMutation.isPending}
            className={loginMutation.isPending ? 'loading' : ''}
          >
            {loginMutation.isPending ? 'Signing In...' : 'Sign In'}
          </button>
          
          <div style={{ marginTop: '1rem', fontSize: '0.875rem', color: '#888' }}>
            Demo credentials: admin@mvp.local / password
          </div>
        </form>
      </main>
    </div>
  )
}