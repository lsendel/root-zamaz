import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { adminAPI } from '../services/api'
import { Role, Permission, UserWithRoles } from '../types/auth'

interface AdminPanelProps {
  onClose: () => void
}

export default function AdminPanel({ onClose }: AdminPanelProps) {
  const { user, isAdmin } = useAuth()
  const [activeTab, setActiveTab] = useState<'permissions' | 'roles' | 'users'>('permissions')
  const [userPermissions, setUserPermissions] = useState<string[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [users, setUsers] = useState<UserWithRoles[]>([])
  const [filteredUsers, setFilteredUsers] = useState<UserWithRoles[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Role form state
  const [newRole, setNewRole] = useState({ name: '', description: '' })
  const [editingRole, setEditingRole] = useState<Role | null>(null)

  // User editing state
  const [editingUser, setEditingUser] = useState<UserWithRoles | null>(null)
  const [userEditForm, setUserEditForm] = useState({
    username: '',
    email: '',
    first_name: '',
    last_name: '',
    is_active: true,
    is_admin: false
  })

  useEffect(() => {
    if (!isAdmin) return

    const loadAdminData = async () => {
      try {
        setLoading(true)
        setError(null)

        // Extract permissions from user roles for display
        const currentUserPermissions = user?.roles?.flatMap(role => 
          role.split(':').length > 1 ? [role] : []
        ) || []
        setUserPermissions(currentUserPermissions)

        // Load all admin data
        const [rolesData, permissionsData, usersData] = await Promise.all([
          adminAPI.getRoles().catch(() => []),
          adminAPI.getPermissions().catch(() => []),
          adminAPI.getUsers().catch(() => [])
        ])

        setRoles(rolesData)
        setPermissions(permissionsData)
        setUsers(usersData)
        setFilteredUsers(usersData)
      } catch (err: any) {
        setError(err.message || 'Failed to load admin data')
      } finally {
        setLoading(false)
      }
    }

    loadAdminData()
  }, [isAdmin, user])

  // Filter users based on search term and status filter
  useEffect(() => {
    let filtered = users

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(user =>
        user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
        `${user.first_name || ''} ${user.last_name || ''}`.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    // Apply status filter
    if (statusFilter) {
      switch (statusFilter) {
        case 'active':
          filtered = filtered.filter(user => user.is_active)
          break
        case 'inactive':
          filtered = filtered.filter(user => !user.is_active)
          break
        case 'admin':
          filtered = filtered.filter(user => user.is_admin)
          break
      }
    }

    setFilteredUsers(filtered)
  }, [users, searchTerm, statusFilter])

  const handleCreateRole = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newRole.name.trim()) return

    try {
      const createdRole = await adminAPI.createRole(newRole)
      setRoles([...roles, createdRole])
      setNewRole({ name: '', description: '' })
    } catch (err: any) {
      setError(err.message || 'Failed to create role')
    }
  }

  const handleUpdateRole = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingRole) return

    try {
      const updatedRole = await adminAPI.updateRole(Number(editingRole.id), {
        name: editingRole.name,
        description: editingRole.description,
        is_active: editingRole.is_active
      })
      setRoles(roles.map(r => r.id === updatedRole.id ? updatedRole : r))
      setEditingRole(null)
    } catch (err: any) {
      setError(err.message || 'Failed to update role')
    }
  }

  const handleDeleteRole = async (roleId: number) => {
    if (!confirm('Are you sure you want to delete this role?')) return

    try {
      await adminAPI.deleteRole(roleId)
      setRoles(roles.filter(r => r.id !== roleId))
    } catch (err: any) {
      setError(err.message || 'Failed to delete role')
    }
  }

  const handleAssignRoleToUser = async (userId: number, roleId: number) => {
    try {
      await adminAPI.assignRoleToUser(userId, roleId)
      // Reload users to show updated roles
      const updatedUsers = await adminAPI.getUsers()
      setUsers(updatedUsers)
      // Filtering will be handled by the useEffect
    } catch (err: any) {
      setError(err.message || 'Failed to assign role to user')
    }
  }

  const handleRemoveRoleFromUser = async (userId: number, roleId: number) => {
    try {
      await adminAPI.removeRoleFromUser(userId, roleId)
      // Reload users to show updated roles
      const updatedUsers = await adminAPI.getUsers()
      setUsers(updatedUsers)
      // Filtering will be handled by the useEffect
    } catch (err: any) {
      setError(err.message || 'Failed to remove role from user')
    }
  }

  const handleEditUser = (user: UserWithRoles) => {
    setEditingUser(user)
    setUserEditForm({
      username: user.username,
      email: user.email,
      first_name: user.first_name || '',
      last_name: user.last_name || '',
      is_active: user.is_active,
      is_admin: user.is_admin
    })
  }

  const handleUpdateUser = async () => {
    if (!editingUser) return

    try {
      await adminAPI.updateUser(editingUser.id, userEditForm)
      // Reload users to show updated information
      const updatedUsers = await adminAPI.getUsers()
      setUsers(updatedUsers)
      setEditingUser(null)
      setUserEditForm({
        username: '',
        email: '',
        first_name: '',
        last_name: '',
        is_active: true,
        is_admin: false
      })
    } catch (err: any) {
      setError(err.message || 'Failed to update user')
    }
  }

  const handleToggleUserStatus = async (userId: number, currentStatus: boolean) => {
    try {
      await adminAPI.updateUser(userId, { is_active: !currentStatus })
      // Reload users to show updated status
      const updatedUsers = await adminAPI.getUsers()
      setUsers(updatedUsers)
    } catch (err: any) {
      setError(err.message || 'Failed to toggle user status')
    }
  }

  const handleToggleAdminStatus = async (userId: number, currentStatus: boolean) => {
    if (!confirm(`Are you sure you want to ${currentStatus ? 'remove admin privileges from' : 'grant admin privileges to'} this user?`)) return

    try {
      await adminAPI.updateUser(userId, { is_admin: !currentStatus })
      // Reload users to show updated admin status
      const updatedUsers = await adminAPI.getUsers()
      setUsers(updatedUsers)
    } catch (err: any) {
      setError(err.message || 'Failed to toggle admin status')
    }
  }

  if (!isAdmin) {
    return (
      <div className="admin-panel">
        <div className="admin-panel-header">
          <h2>Access Denied</h2>
          <button onClick={onClose} className="close-btn">×</button>
        </div>
        <div className="admin-panel-content">
          <p>You do not have administrator privileges.</p>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="admin-panel">
        <div className="admin-panel-header">
          <h2>Admin Panel</h2>
          <button onClick={onClose} className="close-btn">×</button>
        </div>
        <div className="admin-panel-content">
          <p>Loading admin data...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="admin-panel">
      <div className="admin-panel-header">
        <h2>Admin Panel</h2>
        <button onClick={onClose} className="close-btn">×</button>
      </div>

      {error && (
        <div className="error-message">
          {error}
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      <div className="admin-tabs">
        <button 
          className={activeTab === 'permissions' ? 'active' : ''}
          onClick={() => setActiveTab('permissions')}
        >
          My Permissions
        </button>
        <button 
          className={activeTab === 'roles' ? 'active' : ''}
          onClick={() => setActiveTab('roles')}
        >
          Role Management
        </button>
        <button 
          className={activeTab === 'users' ? 'active' : ''}
          onClick={() => setActiveTab('users')}
        >
          User Management
        </button>
      </div>

      <div className="admin-panel-content">
        {activeTab === 'permissions' && (
          <div className="permissions-section">
            <h3>Your Current Permissions</h3>
            <div className="user-info">
              <p><strong>Username:</strong> {user?.username}</p>
              <p><strong>Email:</strong> {user?.email}</p>
              <p><strong>Roles:</strong> {user?.roles?.join(', ') || 'None'}</p>
              <p><strong>Admin Status:</strong> {user?.is_admin ? 'Yes' : 'No'}</p>
            </div>
            
            <h4>Available Permissions:</h4>
            {userPermissions.length > 0 ? (
              <ul className="permissions-list">
                {userPermissions.map((permission, index) => (
                  <li key={index} className="permission-item">
                    {permission}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No specific permissions found. Check your roles for inherited permissions.</p>
            )}

            <h4>All System Permissions:</h4>
            <div className="permissions-grid">
              {permissions.map(permission => (
                <div key={permission.id} className="permission-card">
                  <h5>{permission.name}</h5>
                  <p><strong>Resource:</strong> {permission.resource}</p>
                  <p><strong>Action:</strong> {permission.action}</p>
                  <p><strong>Description:</strong> {permission.description}</p>
                  <span className={`status ${permission.is_active ? 'active' : 'inactive'}`}>
                    {permission.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'roles' && (
          <div className="roles-section">
            <h3>Role Management</h3>
            
            {/* Create new role form */}
            <div className="create-role-form">
              <h4>Create New Role</h4>
              <form onSubmit={handleCreateRole}>
                <div className="form-group">
                  <label>Role Name:</label>
                  <input
                    type="text"
                    value={newRole.name}
                    onChange={(e) => setNewRole({...newRole, name: e.target.value})}
                    placeholder="Enter role name"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Description:</label>
                  <textarea
                    value={newRole.description}
                    onChange={(e) => setNewRole({...newRole, description: e.target.value})}
                    placeholder="Enter role description"
                  />
                </div>
                <button type="submit">Create Role</button>
              </form>
            </div>

            {/* Edit role form */}
            {editingRole && (
              <div className="edit-role-form">
                <h4>Edit Role</h4>
                <form onSubmit={handleUpdateRole}>
                  <div className="form-group">
                    <label>Role Name:</label>
                    <input
                      type="text"
                      value={editingRole.name}
                      onChange={(e) => setEditingRole({...editingRole, name: e.target.value})}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Description:</label>
                    <textarea
                      value={editingRole.description}
                      onChange={(e) => setEditingRole({...editingRole, description: e.target.value})}
                    />
                  </div>
                  <div className="form-group">
                    <label>
                      <input
                        type="checkbox"
                        checked={editingRole.is_active}
                        onChange={(e) => setEditingRole({...editingRole, is_active: e.target.checked})}
                      />
                      Active
                    </label>
                  </div>
                  <div className="form-actions">
                    <button type="submit">Update Role</button>
                    <button type="button" onClick={() => setEditingRole(null)}>Cancel</button>
                  </div>
                </form>
              </div>
            )}

            {/* Roles list */}
            <div className="roles-list">
              <h4>Existing Roles</h4>
              {roles.map(role => (
                <div key={role.id} className="role-card">
                  <div className="role-info">
                    <h5>{role.name}</h5>
                    <p>{role.description}</p>
                    <span className={`status ${role.is_active ? 'active' : 'inactive'}`}>
                      {role.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  <div className="role-actions">
                    <button onClick={() => setEditingRole(role)}>Edit</button>
                    <button onClick={() => handleDeleteRole(role.id)} className="danger">Delete</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'users' && (
          <div className="users-section">
            <h3>User Management</h3>
            
            {/* User Statistics */}
            <div className="user-stats">
              <div className="stat-card">
                <h4>Total Users</h4>
                <span className="stat-number">{users.length}</span>
              </div>
              <div className="stat-card">
                <h4>Active Users</h4>
                <span className="stat-number">{users.filter(u => u.is_active).length}</span>
              </div>
              <div className="stat-card">
                <h4>Admin Users</h4>
                <span className="stat-number">{users.filter(u => u.is_admin).length}</span>
              </div>
              <div className="stat-card">
                <h4>Users with Roles</h4>
                <span className="stat-number">{users.filter(u => u.roles && u.roles.length > 0).length}</span>
              </div>
            </div>

            {/* User Search/Filter */}
            <div className="user-filters">
              <input
                type="text"
                placeholder="Search users by username, email, or name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="user-search"
              />
              <select 
                className="status-filter"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="">All Users</option>
                <option value="active">Active Only</option>
                <option value="inactive">Inactive Only</option>
                <option value="admin">Admins Only</option>
              </select>
            </div>
            
            {/* Display filtered results count */}
            <div className="filter-results">
              <p>Showing {filteredUsers.length} of {users.length} users</p>
              {searchTerm && <p>Search: "{searchTerm}"</p>}
              {statusFilter && <p>Filter: {statusFilter}</p>}
            </div>
            
            <div className="users-list">
              {filteredUsers.map(user => (
                <div key={user.id} className="user-card">
                  <div className="user-info">
                    <div className="user-header">
                      <h5>{user.username}</h5>
                      <span className={`user-badge ${user.is_admin ? 'admin' : 'user'}`}>
                        {user.is_admin ? 'ADMIN' : 'USER'}
                      </span>
                      <span className={`status-badge ${user.is_active ? 'active' : 'inactive'}`}>
                        {user.is_active ? 'ACTIVE' : 'INACTIVE'}
                      </span>
                    </div>
                    <p><strong>ID:</strong> {user.id}</p>
                    <p><strong>Email:</strong> {user.email}</p>
                    <p><strong>Name:</strong> {user.first_name || 'N/A'} {user.last_name || ''}</p>
                    <p><strong>Created:</strong> {new Date(user.created_at).toLocaleDateString()}</p>
                    <p><strong>Last Updated:</strong> {new Date(user.updated_at).toLocaleDateString()}</p>
                    <p><strong>Roles:</strong> {user.roles?.map(r => r.name).join(', ') || 'None assigned'}</p>
                    <p><strong>Role Count:</strong> {user.roles?.length || 0}</p>
                  </div>
                  <div className="user-actions">
                    <div className="user-role-management">
                      <h6>Role Management:</h6>
                      <div className="role-assignments">
                        {roles.map(role => {
                          const hasRole = user.roles?.some(r => r.id === role.id)
                          return (
                            <div key={role.id} className="role-assignment">
                              <span className={`role-name ${hasRole ? 'assigned' : ''}`}>
                                {role.name}
                              </span>
                              {hasRole ? (
                                <button 
                                  onClick={() => handleRemoveRoleFromUser(user.id, role.id)}
                                  className="remove-role"
                                  title="Remove this role from user"
                                >
                                  ✕ Remove
                                </button>
                              ) : (
                                <button 
                                  onClick={() => handleAssignRoleToUser(user.id, role.id)}
                                  className="assign-role"
                                  title="Assign this role to user"
                                >
                                  + Assign
                                </button>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                    
                    <div className="user-management-actions">
                      <h6>Account Actions:</h6>
                      <div className="action-buttons">
                        <button 
                          className="edit-user"
                          onClick={() => handleEditUser(user)}
                          title="Edit user details"
                        >
                          📝 Edit User
                        </button>
                        <button 
                          className={`toggle-status ${user.is_active ? 'deactivate' : 'activate'}`}
                          onClick={() => handleToggleUserStatus(user.id, user.is_active)}
                          title={`${user.is_active ? 'Deactivate' : 'Activate'} this user`}
                        >
                          {user.is_active ? '🚫 Deactivate' : '✅ Activate'}
                        </button>
                        <button 
                          className={`toggle-admin ${user.is_admin ? 'remove-admin' : 'make-admin'}`}
                          onClick={() => handleToggleAdminStatus(user.id, user.is_admin)}
                          title={`${user.is_admin ? 'Remove admin privileges' : 'Grant admin privileges'}`}
                        >
                          {user.is_admin ? '👤 Remove Admin' : '👑 Make Admin'}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* User Edit Modal */}
      {editingUser && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>Edit User: {editingUser.username}</h3>
              <button 
                onClick={() => setEditingUser(null)}
                className="close-btn"
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label htmlFor="edit-username">Username</label>
                <input
                  id="edit-username"
                  type="text"
                  value={userEditForm.username}
                  onChange={(e) => setUserEditForm({...userEditForm, username: e.target.value})}
                  placeholder="Username"
                />
              </div>
              <div className="form-group">
                <label htmlFor="edit-email">Email</label>
                <input
                  id="edit-email"
                  type="email"
                  value={userEditForm.email}
                  onChange={(e) => setUserEditForm({...userEditForm, email: e.target.value})}
                  placeholder="Email"
                />
              </div>
              <div className="form-group">
                <label htmlFor="edit-first-name">First Name</label>
                <input
                  id="edit-first-name"
                  type="text"
                  value={userEditForm.first_name}
                  onChange={(e) => setUserEditForm({...userEditForm, first_name: e.target.value})}
                  placeholder="First Name"
                />
              </div>
              <div className="form-group">
                <label htmlFor="edit-last-name">Last Name</label>
                <input
                  id="edit-last-name"
                  type="text"
                  value={userEditForm.last_name}
                  onChange={(e) => setUserEditForm({...userEditForm, last_name: e.target.value})}
                  placeholder="Last Name"
                />
              </div>
              <div className="form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={userEditForm.is_active}
                    onChange={(e) => setUserEditForm({...userEditForm, is_active: e.target.checked})}
                  />
                  Active User
                </label>
              </div>
              <div className="form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={userEditForm.is_admin}
                    onChange={(e) => setUserEditForm({...userEditForm, is_admin: e.target.checked})}
                  />
                  Administrator
                </label>
              </div>
            </div>
            <div className="modal-footer">
              <button 
                onClick={() => setEditingUser(null)}
                className="cancel-btn"
              >
                Cancel
              </button>
              <button 
                onClick={handleUpdateUser}
                className="save-btn"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}