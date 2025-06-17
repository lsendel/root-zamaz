import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  
  const { login, isAuthenticated, error, isLoading } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard')
    }
  }, [isAuthenticated, navigate])

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setIsSubmitting(true)

    try {
      await login({ username, password })
      navigate('/dashboard')
    } catch (error) {
      // Error is handled by the auth context
    } finally {
      setIsSubmitting(false)
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
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={isSubmitting}
              placeholder="Enter your username"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={isSubmitting}
              placeholder="Enter your password"
            />
          </div>
          
          <button 
            type="submit" 
            disabled={isSubmitting}
            className={isSubmitting ? 'loading' : ''}
          >
            {isSubmitting ? 'Signing In...' : 'Sign In'}
          </button>
          
          <div style={{ marginTop: '1rem', fontSize: '0.875rem', color: '#888' }}>
            Demo credentials: admin / password
          </div>
        </form>
      </main>
    </div>
  )
}