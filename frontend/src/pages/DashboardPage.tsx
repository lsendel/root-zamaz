import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { deviceAPI, healthAPI } from '../services/api'
import { DeviceAttestation } from '../types/auth'
import AdminPanel from '../components/AdminPanel'

export default function DashboardPage() {
  const { user, isAdmin, logout } = useAuth()
  
  const [devices, setDevices] = useState<DeviceAttestation[]>([])
  const [systemHealth, setSystemHealth] = useState<{ status: string; services: Record<string, string> } | null>(null)
  const [loading, setLoading] = useState(true)
  const [showAdminPanel, setShowAdminPanel] = useState(false)

  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        // Load devices
        try {
          const devicesData = await deviceAPI.getDevices()
          setDevices(devicesData || []) // Handle null response
        } catch (error) {
          console.log('Devices API error:', error)
          setDevices([]) // Set empty array if API fails
        }

        // Load system health
        try {
          const healthData = await healthAPI.getSystemHealth()
          setSystemHealth(healthData)
        } catch (error) {
          console.log('Health API error:', error)
          setSystemHealth(null) // Set null if API fails
        }
      } catch (error) {
        console.error('Failed to load dashboard data:', error)
      } finally {
        setLoading(false)
      }
    }

    loadDashboardData()
  }, [])

  const handleLogout = async () => {
    await logout()
  }

  const getTrustLevelClass = (level: number) => {
    if (level >= 80) return 'trust-high'
    if (level >= 60) return 'trust-medium'
    return 'trust-low'
  }

  const getServiceStatusClass = (status: string) => {
    switch (status) {
      case 'healthy': return 'status-online'
      case 'degraded': return 'status-warning'
      case 'unhealthy': return 'status-offline'
      default: return 'status-offline'
    }
  }

  if (loading) {
    return (
      <div className="app">
        <div>Loading dashboard...</div>
      </div>
    )
  }

  return (
    <div className="app">
      <header className="header">
        <h1>Zero Trust Dashboard</h1>
        <nav className="nav">
          <div className="user-menu" data-testid="user-menu">
            <span>Welcome, {user?.first_name || user?.username}</span>
            <Link to="/profile" className="profile-link">
              👤 Profile
            </Link>
            {isAdmin && (
              <button onClick={() => setShowAdminPanel(true)} className="admin-btn">
                Admin Panel
              </button>
            )}
            <button onClick={handleLogout}>Logout</button>
          </div>
        </nav>
      </header>

      <main className="main-content">
        <div className="dashboard-grid">
          <div className="dashboard-card">
            <h3>System Health</h3>
            <div>
              <div>
                Overall Status: 
                <span className={`status-indicator ${getServiceStatusClass(systemHealth?.status || 'unknown')}`}></span>
                {systemHealth?.status || 'Unknown'}
              </div>
              {systemHealth?.services && (
                <div style={{ marginTop: '1rem' }}>
                  <h4>Services:</h4>
                  {Object.entries(systemHealth.services).map(([service, status]) => (
                    <div key={service} style={{ display: 'flex', justifyContent: 'space-between', margin: '0.5rem 0' }}>
                      <span>{service}:</span>
                      <span>
                        <span className={`status-indicator ${getServiceStatusClass(status)}`}></span>
                        {status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="dashboard-card">
            <h3>Device Attestations</h3>
            {devices.length === 0 ? (
              <p>No devices registered</p>
            ) : (
              <ul className="device-list">
                {devices.map((device) => (
                  <li key={device.id}>
                    <div>
                      <strong>{device.deviceId}</strong>
                      <div style={{ fontSize: '0.875rem', color: '#888' }}>
                        {device.attestationData.platform}
                        {device.isVerified && ' • Verified'}
                      </div>
                    </div>
                    <span className={`trust-level ${getTrustLevelClass(device.trustLevel)}`}>
                      Trust: {device.trustLevel}%
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="dashboard-card">
            <h3>Recent Activity</h3>
            <div>
              <div style={{ padding: '0.5rem 0', borderBottom: '1px solid #333' }}>
                <div>Login successful</div>
                <div style={{ fontSize: '0.875rem', color: '#888' }}>
                  {new Date().toLocaleString()}
                </div>
              </div>
              <div style={{ padding: '0.5rem 0', borderBottom: '1px solid #333' }}>
                <div>Device attestation completed</div>
                <div style={{ fontSize: '0.875rem', color: '#888' }}>
                  {new Date(Date.now() - 300000).toLocaleString()}
                </div>
              </div>
              <div style={{ padding: '0.5rem 0' }}>
                <div>System health check</div>
                <div style={{ fontSize: '0.875rem', color: '#888' }}>
                  {new Date(Date.now() - 600000).toLocaleString()}
                </div>
              </div>
            </div>
          </div>

          <div className="dashboard-card">
            <h3>User Information</h3>
            <div>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Email:</strong> {user?.email}
              </div>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Name:</strong> {user?.first_name} {user?.last_name}
              </div>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Status:</strong> {user?.is_active ? 'Active' : 'Inactive'}
              </div>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Admin:</strong> {user?.is_admin ? 'Yes' : 'No'}
              </div>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Roles:</strong> {user?.roles?.join(', ') || 'None'}
              </div>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Member since:</strong> {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
              </div>
            </div>
          </div>
        </div>
      </main>

      {showAdminPanel && (
        <div className="modal-overlay">
          <AdminPanel onClose={() => setShowAdminPanel(false)} />
        </div>
      )}
    </div>
  )
}