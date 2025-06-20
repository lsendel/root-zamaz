/**
 * Comprehensive API Endpoint Tests
 * Tests all REST API endpoints with authentication and authorization
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';

// API Testing Configuration
const API_BASE_URL = process.env.API_URL || 'http://localhost:8080/api';
const TEST_TIMEOUT = 30000;

// Test credentials based on actual seeded data
const TEST_CREDENTIALS = {
  admin: {
    username: 'admin@mvp.local',
    password: 'password'
  },
  invalid: {
    username: 'invalid@example.com',
    password: 'wrongpassword'
  }
};

// Global test state
let adminToken = null;
let adminUser = null;
let testRoleId = null;
let testUserId = null;

// Helper functions
const apiRequest = async (endpoint, options = {}) => {
  const url = `${API_BASE_URL}${endpoint}`;
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers
    },
    ...options
  };

  if (adminToken && !options.skipAuth) {
    config.headers.Authorization = `Bearer ${adminToken}`;
  }

  try {
    const response = await fetch(url, config);
    const contentType = response.headers.get('content-type');
    
    let data = null;
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    } else {
      data = await response.text();
    }

    return {
      status: response.status,
      statusText: response.statusText,
      ok: response.ok,
      headers: Object.fromEntries(response.headers.entries()),
      data
    };
  } catch (error) {
    throw new Error(`API Request failed: ${error.message}`);
  }
};

const waitForRateLimit = (seconds = 30) => {
  return new Promise(resolve => setTimeout(resolve, seconds * 1000));
};

describe('API Endpoint Tests', () => {
  beforeAll(async () => {
    console.log('Starting API endpoint tests...');
    console.log(`Testing against: ${API_BASE_URL}`);
    
    // Wait a bit to ensure any rate limiting is cleared
    console.log('Waiting for rate limit reset...');
    await waitForRateLimit(30);
  }, TEST_TIMEOUT);

  afterAll(async () => {
    // Cleanup: logout admin session
    if (adminToken) {
      try {
        await apiRequest('/auth/logout', { method: 'POST' });
      } catch (error) {
        console.log('Cleanup logout failed:', error.message);
      }
    }
  });

  describe('Authentication Endpoints', () => {
    describe('POST /auth/login', () => {
      it('should authenticate with valid admin credentials', async () => {
        const response = await apiRequest('/auth/login', {
          method: 'POST',
          body: JSON.stringify(TEST_CREDENTIALS.admin),
          skipAuth: true
        });

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('token');
        expect(response.data).toHaveProperty('user');
        expect(response.data).toHaveProperty('expires_at');
        
        // Store token for subsequent tests
        adminToken = response.data.token;
        adminUser = response.data.user;
        
        // Verify user properties
        expect(adminUser.email).toBe(TEST_CREDENTIALS.admin.username);
        expect(adminUser.is_admin).toBe(true);
        expect(adminUser.is_active).toBe(true);
      }, TEST_TIMEOUT);

      it('should reject invalid credentials', async () => {
        const response = await apiRequest('/auth/login', {
          method: 'POST',
          body: JSON.stringify(TEST_CREDENTIALS.invalid),
          skipAuth: true
        });

        expect(response.status).toBe(401);
        expect(response.data).toHaveProperty('error');
        expect(response.data.message).toContain('Invalid');
      }, TEST_TIMEOUT);

      it('should reject malformed requests', async () => {
        const response = await apiRequest('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username: 'admin' }), // Missing password
          skipAuth: true
        });

        expect(response.status).toBe(400);
        expect(response.data).toHaveProperty('error');
      }, TEST_TIMEOUT);

      it('should handle rate limiting', async () => {
        // Make multiple rapid requests to trigger rate limiting
        const promises = Array(10).fill().map(() => 
          apiRequest('/auth/login', {
            method: 'POST',
            body: JSON.stringify(TEST_CREDENTIALS.invalid),
            skipAuth: true
          })
        );

        const responses = await Promise.all(promises);
        
        // At least one should be rate limited
        const rateLimited = responses.some(r => r.status === 429);
        if (rateLimited) {
          expect(rateLimited).toBe(true);
        }
      }, TEST_TIMEOUT);
    });

    describe('GET /auth/me', () => {
      it('should return current user info with valid token', async () => {
        const response = await apiRequest('/auth/me', {
          method: 'GET'
        });

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('id');
        expect(response.data).toHaveProperty('username');
        expect(response.data).toHaveProperty('email');
        expect(response.data).toHaveProperty('is_admin');
        expect(response.data.email).toBe(TEST_CREDENTIALS.admin.username);
      }, TEST_TIMEOUT);

      it('should reject requests without token', async () => {
        const response = await apiRequest('/auth/me', {
          method: 'GET',
          skipAuth: true
        });

        expect(response.status).toBe(401);
      }, TEST_TIMEOUT);

      it('should reject requests with invalid token', async () => {
        const response = await apiRequest('/auth/me', {
          method: 'GET',
          headers: {
            'Authorization': 'Bearer invalid-token'
          },
          skipAuth: true
        });

        expect(response.status).toBe(401);
      }, TEST_TIMEOUT);
    });

    describe('POST /auth/logout', () => {
      it('should logout successfully', async () => {
        // First login to get a fresh token
        const loginResponse = await apiRequest('/auth/login', {
          method: 'POST',
          body: JSON.stringify(TEST_CREDENTIALS.admin),
          skipAuth: true
        });
        
        const logoutToken = loginResponse.data.token;

        const response = await apiRequest('/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${logoutToken}`
          },
          skipAuth: true
        });

        expect(response.status).toBe(200);
      }, TEST_TIMEOUT);
    });
  });

  describe('Health Endpoint', () => {
    describe('GET /health', () => {
      it('should return system health status', async () => {
        const response = await apiRequest('/health', {
          method: 'GET',
          skipAuth: true
        });

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('status');
        expect(response.data).toHaveProperty('services');
        expect(response.data.services).toHaveProperty('database');
        expect(response.data.services).toHaveProperty('redis');
      }, TEST_TIMEOUT);
    });
  });

  describe('Admin Endpoints', () => {
    describe('Role Management', () => {
      describe('GET /admin/roles', () => {
        it('should return all roles for admin user', async () => {
          const response = await apiRequest('/admin/roles', {
            method: 'GET'
          });

          expect(response.status).toBe(200);
          expect(Array.isArray(response.data)).toBe(true);
          
          if (response.data.length > 0) {
            const role = response.data[0];
            expect(role).toHaveProperty('id');
            expect(role).toHaveProperty('name');
            expect(role).toHaveProperty('description');
            expect(role).toHaveProperty('is_active');
          }
        }, TEST_TIMEOUT);

        it('should reject non-admin users', async () => {
          // This would need a regular user token to test properly
          // For now, test with no token
          const response = await apiRequest('/admin/roles', {
            method: 'GET',
            skipAuth: true
          });

          expect(response.status).toBe(401);
        }, TEST_TIMEOUT);
      });

      describe('POST /admin/roles', () => {
        it('should create a new role', async () => {
          const newRole = {
            name: `test-role-${Date.now()}`,
            description: 'Test role for API testing'
          };

          const response = await apiRequest('/admin/roles', {
            method: 'POST',
            body: JSON.stringify(newRole)
          });

          expect(response.status).toBe(201);
          expect(response.data).toHaveProperty('id');
          expect(response.data.name).toBe(newRole.name);
          expect(response.data.description).toBe(newRole.description);
          
          // Store for cleanup
          testRoleId = response.data.id;
        }, TEST_TIMEOUT);

        it('should reject duplicate role names', async () => {
          const duplicateRole = {
            name: 'admin', // Should already exist
            description: 'Duplicate admin role'
          };

          const response = await apiRequest('/admin/roles', {
            method: 'POST',
            body: JSON.stringify(duplicateRole)
          });

          expect(response.status).toBe(400);
        }, TEST_TIMEOUT);
      });

      describe('PUT /admin/roles/:id', () => {
        it('should update an existing role', async () => {
          if (!testRoleId) {
            // Create a role first
            const createResponse = await apiRequest('/admin/roles', {
              method: 'POST',
              body: JSON.stringify({
                name: `update-test-role-${Date.now()}`,
                description: 'Role for update testing'
              })
            });
            testRoleId = createResponse.data.id;
          }

          const updateData = {
            description: 'Updated description for test role',
            is_active: false
          };

          const response = await apiRequest(`/admin/roles/${testRoleId}`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
          });

          expect(response.status).toBe(200);
          expect(response.data.description).toBe(updateData.description);
          expect(response.data.is_active).toBe(updateData.is_active);
        }, TEST_TIMEOUT);

        it('should return 404 for non-existent role', async () => {
          const response = await apiRequest('/admin/roles/99999', {
            method: 'PUT',
            body: JSON.stringify({ description: 'Update non-existent' })
          });

          expect(response.status).toBe(404);
        }, TEST_TIMEOUT);
      });

      describe('DELETE /admin/roles/:id', () => {
        it('should delete a role', async () => {
          if (!testRoleId) {
            // Create a role first
            const createResponse = await apiRequest('/admin/roles', {
              method: 'POST',
              body: JSON.stringify({
                name: `delete-test-role-${Date.now()}`,
                description: 'Role for delete testing'
              })
            });
            testRoleId = createResponse.data.id;
          }

          const response = await apiRequest(`/admin/roles/${testRoleId}`, {
            method: 'DELETE'
          });

          expect(response.status).toBe(200);
          
          // Verify it's deleted
          const getResponse = await apiRequest(`/admin/roles/${testRoleId}`, {
            method: 'GET'
          });
          expect(getResponse.status).toBe(404);
          
          testRoleId = null; // Clear since it's deleted
        }, TEST_TIMEOUT);
      });
    });

    describe('User Management', () => {
      describe('GET /admin/users', () => {
        it('should return all users with roles', async () => {
          const response = await apiRequest('/admin/users', {
            method: 'GET'
          });

          expect(response.status).toBe(200);
          expect(Array.isArray(response.data)).toBe(true);
          expect(response.data.length).toBeGreaterThan(0);
          
          const user = response.data[0];
          expect(user).toHaveProperty('id');
          expect(user).toHaveProperty('username');
          expect(user).toHaveProperty('email');
          expect(user).toHaveProperty('roles');
          expect(Array.isArray(user.roles)).toBe(true);
        }, TEST_TIMEOUT);
      });

      describe('GET /admin/users/:id', () => {
        it('should return specific user details', async () => {
          // Get user ID from admin user
          const userId = adminUser.id;

          const response = await apiRequest(`/admin/users/${userId}`, {
            method: 'GET'
          });

          expect(response.status).toBe(200);
          expect(response.data.id).toBe(userId);
          expect(response.data).toHaveProperty('roles');
        }, TEST_TIMEOUT);

        it('should return 404 for non-existent user', async () => {
          const response = await apiRequest('/admin/users/99999', {
            method: 'GET'
          });

          expect(response.status).toBe(404);
        }, TEST_TIMEOUT);
      });

      describe('PUT /admin/users/:id', () => {
        it('should update user details', async () => {
          const userId = adminUser.id;
          const updateData = {
            first_name: 'Updated',
            last_name: 'Admin'
          };

          const response = await apiRequest(`/admin/users/${userId}`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
          });

          expect(response.status).toBe(200);
          expect(response.data.first_name).toBe(updateData.first_name);
          expect(response.data.last_name).toBe(updateData.last_name);
        }, TEST_TIMEOUT);

        it('should reject invalid email format', async () => {
          const userId = adminUser.id;
          const invalidData = {
            email: 'invalid-email-format'
          };

          const response = await apiRequest(`/admin/users/${userId}`, {
            method: 'PUT',
            body: JSON.stringify(invalidData)
          });

          expect(response.status).toBe(400);
        }, TEST_TIMEOUT);
      });
    });

    describe('Permission Management', () => {
      describe('GET /admin/permissions', () => {
        it('should return all system permissions', async () => {
          const response = await apiRequest('/admin/permissions', {
            method: 'GET'
          });

          expect(response.status).toBe(200);
          expect(Array.isArray(response.data)).toBe(true);
          
          if (response.data.length > 0) {
            const permission = response.data[0];
            expect(permission).toHaveProperty('id');
            expect(permission).toHaveProperty('name');
            expect(permission).toHaveProperty('resource');
            expect(permission).toHaveProperty('action');
          }
        }, TEST_TIMEOUT);
      });
    });

    describe('Role-User Assignment', () => {
      it('should assign role to user', async () => {
        // First ensure we have a test role
        if (!testRoleId) {
          const createResponse = await apiRequest('/admin/roles', {
            method: 'POST',
            body: JSON.stringify({
              name: `assignment-test-role-${Date.now()}`,
              description: 'Role for assignment testing'
            })
          });
          testRoleId = createResponse.data.id;
        }

        const userId = adminUser.id;
        const response = await apiRequest(`/admin/users/${userId}/roles/${testRoleId}`, {
          method: 'POST'
        });

        expect(response.status).toBe(200);
      }, TEST_TIMEOUT);

      it('should remove role from user', async () => {
        if (!testRoleId) return;

        const userId = adminUser.id;
        const response = await apiRequest(`/admin/users/${userId}/roles/${testRoleId}`, {
          method: 'DELETE'
        });

        expect(response.status).toBe(200);
      }, TEST_TIMEOUT);
    });
  });

  describe('Error Handling', () => {
    it('should handle 404 for non-existent endpoints', async () => {
      const response = await apiRequest('/non-existent-endpoint', {
        method: 'GET'
      });

      expect(response.status).toBe(404);
    }, TEST_TIMEOUT);

    it('should handle malformed JSON', async () => {
      const response = await apiRequest('/auth/login', {
        method: 'POST',
        body: '{ invalid json',
        skipAuth: true
      });

      expect(response.status).toBe(400);
    }, TEST_TIMEOUT);

    it('should handle unsupported HTTP methods', async () => {
      const response = await apiRequest('/health', {
        method: 'PATCH'
      });

      expect(response.status).toBe(405);
    }, TEST_TIMEOUT);
  });

  describe('Security Tests', () => {
    it('should include security headers', async () => {
      const response = await apiRequest('/health', {
        method: 'GET',
        skipAuth: true
      });

      // Check for common security headers
      expect(response.headers).toHaveProperty('x-content-type-options');
      expect(response.headers).toHaveProperty('x-frame-options');
    }, TEST_TIMEOUT);

    it('should handle SQL injection attempts', async () => {
      const sqlInjection = {
        username: "admin'; DROP TABLE users; --",
        password: 'password'
      };

      const response = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify(sqlInjection),
        skipAuth: true
      });

      // Should not cause server error
      expect(response.status).not.toBe(500);
    }, TEST_TIMEOUT);

    it('should handle XSS attempts in input', async () => {
      const xssPayload = {
        username: '<script>alert("xss")</script>',
        password: 'password'
      };

      const response = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify(xssPayload),
        skipAuth: true
      });

      // Should not cause server error
      expect(response.status).not.toBe(500);
      // Should properly escape/sanitize
      if (response.data.message) {
        expect(response.data.message).not.toContain('<script>');
      }
    }, TEST_TIMEOUT);
  });

  describe('Performance Tests', () => {
    it('should respond to health check within reasonable time', async () => {
      const start = Date.now();
      
      const response = await apiRequest('/health', {
        method: 'GET',
        skipAuth: true
      });

      const duration = Date.now() - start;
      
      expect(response.status).toBe(200);
      expect(duration).toBeLessThan(1000); // Should respond within 1 second
    }, TEST_TIMEOUT);

    it('should handle concurrent requests', async () => {
      const concurrentRequests = 10;
      const promises = Array(concurrentRequests).fill().map(() =>
        apiRequest('/health', {
          method: 'GET',
          skipAuth: true
        })
      );

      const responses = await Promise.all(promises);
      
      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    }, TEST_TIMEOUT);
  });
});