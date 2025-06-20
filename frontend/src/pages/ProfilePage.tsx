import React, { useState, useEffect } from 'react'
import { useAuthStore } from '../stores/auth-store'
import { authApi } from '../services/api'
import { useUIStore } from '../stores/ui-store'
import { User } from '../types/auth'

export default function ProfilePage() {
  const user = useAuthStore(state => state.user)
  const setUser = useAuthStore(state => state.setUser)
  const addNotification = useUIStore(state => state.addNotification)
  
  const [isEditing, setIsEditing] = useState(false)
  const [loading, setLoading] = useState(false)
  const [profileForm, setProfileForm] = useState({
    username: '',
    email: '',
    first_name: '',
    last_name: ''
  })

  useEffect(() => {
    if (user) {
      setProfileForm({
        username: user.username || '',
        email: user.email || '',
        first_name: user.first_name || '',
        last_name: user.last_name || ''
      })
    }
  }, [user])

  const handleUpdateProfile = async () => {
    if (!user) return

    try {
      setLoading(true)
      
      // Use the auth API to update current user profile
      // Note: This would need a PUT /auth/me endpoint or similar
      const response = await fetch('/api/auth/me', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${useAuthStore.getState().token}`
        },
        body: JSON.stringify(profileForm)
      })

      if (!response.ok) {
        throw new Error('Failed to update profile')
      }

      const updatedUser = await response.json()
      setUser(updatedUser)
      setIsEditing(false)
      
      addNotification({
        type: 'success',
        title: 'Profile Updated',
        message: 'Your profile has been updated successfully'
      })
    } catch (error: any) {
      addNotification({
        type: 'error',
        title: 'Update Failed',
        message: error.message || 'Failed to update profile'
      })
    } finally {
      setLoading(false)
    }
  }

  const handleCancel = () => {
    if (user) {
      setProfileForm({
        username: user.username || '',
        email: user.email || '',
        first_name: user.first_name || '',
        last_name: user.last_name || ''
      })
    }
    setIsEditing(false)
  }

  if (!user) {
    return (
      <div className="profile-page">
        <div className="error-message">
          <h2>Access Denied</h2>
          <p>You must be logged in to view your profile.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="profile-page">
      <div className="profile-header">
        <h1>User Profile</h1>
        <p>Manage your account information and preferences</p>
      </div>

      <div className="profile-content">
        <div className="profile-section">
          <div className="section-header">
            <h2>Personal Information</h2>
            {!isEditing ? (
              <button 
                onClick={() => setIsEditing(true)}
                className="edit-button"
              >
                📝 Edit Profile
              </button>
            ) : (
              <div className="edit-actions">
                <button 
                  onClick={handleCancel}
                  className="cancel-button"
                  disabled={loading}
                >
                  Cancel
                </button>
                <button 
                  onClick={handleUpdateProfile}
                  className="save-button"
                  disabled={loading}
                >
                  {loading ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            )}
          </div>

          <div className="profile-info">
            {!isEditing ? (
              <div className="info-display">
                <div className="info-item">
                  <label>Username:</label>
                  <span>{user.username}</span>
                </div>
                <div className="info-item">
                  <label>Email:</label>
                  <span>{user.email}</span>
                </div>
                <div className="info-item">
                  <label>First Name:</label>
                  <span>{user.first_name || 'Not set'}</span>
                </div>
                <div className="info-item">
                  <label>Last Name:</label>
                  <span>{user.last_name || 'Not set'}</span>
                </div>
                <div className="info-item">
                  <label>Account Type:</label>
                  <span className={`account-type ${user.is_admin ? 'admin' : 'user'}`}>
                    {user.is_admin ? 'Administrator' : 'User'}
                  </span>
                </div>
                <div className="info-item">
                  <label>Status:</label>
                  <span className={`status ${user.is_active ? 'active' : 'inactive'}`}>
                    {user.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
                <div className="info-item">
                  <label>Member Since:</label>
                  <span>{new Date(user.created_at).toLocaleDateString()}</span>
                </div>
                <div className="info-item">
                  <label>Last Updated:</label>
                  <span>{new Date(user.updated_at).toLocaleDateString()}</span>
                </div>
                {user.last_login_at && (
                  <div className="info-item">
                    <label>Last Login:</label>
                    <span>{new Date(user.last_login_at).toLocaleString()}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="info-edit">
                <div className="form-group">
                  <label htmlFor="username">Username</label>
                  <input
                    id="username"
                    type="text"
                    value={profileForm.username}
                    onChange={(e) => setProfileForm({...profileForm, username: e.target.value})}
                    placeholder="Username"
                    disabled={loading}
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="email">Email</label>
                  <input
                    id="email"
                    type="email"
                    value={profileForm.email}
                    onChange={(e) => setProfileForm({...profileForm, email: e.target.value})}
                    placeholder="Email address"
                    disabled={loading}
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="first_name">First Name</label>
                  <input
                    id="first_name"
                    type="text"
                    value={profileForm.first_name}
                    onChange={(e) => setProfileForm({...profileForm, first_name: e.target.value})}
                    placeholder="First name"
                    disabled={loading}
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="last_name">Last Name</label>
                  <input
                    id="last_name"
                    type="text"
                    value={profileForm.last_name}
                    onChange={(e) => setProfileForm({...profileForm, last_name: e.target.value})}
                    placeholder="Last name"
                    disabled={loading}
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="profile-section">
          <h2>Account Security</h2>
          <div className="security-info">
            <div className="info-item">
              <label>Two-Factor Authentication:</label>
              <span className={`mfa-status ${user.mfa_enabled ? 'enabled' : 'disabled'}`}>
                {user.mfa_enabled ? 'Enabled' : 'Disabled'}
              </span>
              <button 
                className="security-button"
                onClick={() => addNotification({
                  type: 'info',
                  title: 'Feature Coming Soon',
                  message: 'Two-factor authentication management will be available soon'
                })}
              >
                {user.mfa_enabled ? 'Manage' : 'Enable'} 2FA
              </button>
            </div>
            
            <div className="info-item">
              <label>Password:</label>
              <span>••••••••</span>
              <button 
                className="security-button"
                onClick={() => addNotification({
                  type: 'info',
                  title: 'Feature Coming Soon',
                  message: 'Password change functionality will be available soon'
                })}
              >
                Change Password
              </button>
            </div>

            {user.failed_login_attempts > 0 && (
              <div className="info-item">
                <label>Failed Login Attempts:</label>
                <span className="warning">{user.failed_login_attempts}</span>
              </div>
            )}

            {user.account_locked_until && (
              <div className="info-item">
                <label>Account Locked Until:</label>
                <span className="error">
                  {new Date(user.account_locked_until).toLocaleString()}
                </span>
              </div>
            )}

            {user.last_login_ip && (
              <div className="info-item">
                <label>Last Login IP:</label>
                <span>{user.last_login_ip}</span>
              </div>
            )}
          </div>
        </div>

        {user.roles && user.roles.length > 0 && (
          <div className="profile-section">
            <h2>Roles & Permissions</h2>
            <div className="roles-info">
              <div className="roles-list">
                {user.roles.map((role, index) => (
                  <span key={index} className="role-badge">
                    {role}
                  </span>
                ))}
              </div>
              <p className="roles-note">
                Your roles determine what actions you can perform in the system.
                Contact an administrator if you need additional permissions.
              </p>
            </div>
          </div>
        )}
      </div>

      <style jsx>{`
        .profile-page {
          max-width: 800px;
          margin: 0 auto;
          padding: 2rem;
          background: #f8f9fa;
          min-height: 100vh;
        }

        .profile-header {
          text-align: center;
          margin-bottom: 2rem;
        }

        .profile-header h1 {
          color: #2c3e50;
          margin-bottom: 0.5rem;
        }

        .profile-header p {
          color: #6c757d;
        }

        .profile-content {
          display: flex;
          flex-direction: column;
          gap: 2rem;
        }

        .profile-section {
          background: white;
          border-radius: 8px;
          padding: 1.5rem;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .section-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1rem;
          border-bottom: 1px solid #eee;
          padding-bottom: 1rem;
        }

        .section-header h2 {
          margin: 0;
          color: #2c3e50;
        }

        .edit-actions {
          display: flex;
          gap: 0.5rem;
        }

        .edit-button, .save-button, .cancel-button, .security-button {
          padding: 0.5rem 1rem;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-size: 0.9rem;
          transition: background-color 0.2s;
        }

        .edit-button {
          background: #007bff;
          color: white;
        }

        .edit-button:hover {
          background: #0056b3;
        }

        .save-button {
          background: #28a745;
          color: white;
        }

        .save-button:hover:not(:disabled) {
          background: #1e7e34;
        }

        .cancel-button {
          background: #6c757d;
          color: white;
        }

        .cancel-button:hover:not(:disabled) {
          background: #545b62;
        }

        .security-button {
          background: #17a2b8;
          color: white;
          font-size: 0.8rem;
          padding: 0.25rem 0.5rem;
          margin-left: 1rem;
        }

        .security-button:hover {
          background: #117a8b;
        }

        .info-display {
          display: grid;
          gap: 1rem;
        }

        .info-item {
          display: flex;
          align-items: center;
          padding: 0.5rem 0;
          border-bottom: 1px solid #f0f0f0;
        }

        .info-item label {
          font-weight: 600;
          min-width: 150px;
          color: #495057;
        }

        .info-item span {
          flex: 1;
        }

        .account-type.admin {
          color: #dc3545;
          font-weight: 600;
        }

        .account-type.user {
          color: #28a745;
        }

        .status.active {
          color: #28a745;
          font-weight: 600;
        }

        .status.inactive {
          color: #dc3545;
          font-weight: 600;
        }

        .mfa-status.enabled {
          color: #28a745;
          font-weight: 600;
        }

        .mfa-status.disabled {
          color: #ffc107;
          font-weight: 600;
        }

        .warning {
          color: #ffc107;
          font-weight: 600;
        }

        .error {
          color: #dc3545;
          font-weight: 600;
        }

        .info-edit {
          display: grid;
          gap: 1rem;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .form-group label {
          font-weight: 600;
          color: #495057;
        }

        .form-group input {
          padding: 0.75rem;
          border: 1px solid #ced4da;
          border-radius: 4px;
          font-size: 1rem;
        }

        .form-group input:focus {
          outline: none;
          border-color: #007bff;
          box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
        }

        .form-group input:disabled {
          background: #f8f9fa;
          cursor: not-allowed;
        }

        .roles-list {
          display: flex;
          flex-wrap: wrap;
          gap: 0.5rem;
          margin-bottom: 1rem;
        }

        .role-badge {
          background: #007bff;
          color: white;
          padding: 0.25rem 0.75rem;
          border-radius: 12px;
          font-size: 0.9rem;
          font-weight: 500;
        }

        .roles-note {
          color: #6c757d;
          font-style: italic;
          margin: 0;
        }

        .error-message {
          text-align: center;
          padding: 2rem;
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .error-message h2 {
          color: #dc3545;
          margin-bottom: 1rem;
        }

        @media (max-width: 768px) {
          .profile-page {
            padding: 1rem;
          }

          .section-header {
            flex-direction: column;
            align-items: stretch;
            gap: 1rem;
          }

          .edit-actions {
            justify-content: center;
          }

          .info-item {
            flex-direction: column;
            align-items: stretch;
            gap: 0.25rem;
          }

          .info-item label {
            min-width: auto;
          }

          .security-button {
            margin-left: 0;
            margin-top: 0.5rem;
            align-self: flex-start;
          }
        }
      `}</style>
    </div>
  )
}