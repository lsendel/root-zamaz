// K6 Load Testing Script for Zero Trust Authentication System
// Run with: k6 run --out influxdb=http://localhost:8086/k6 k6-load-test.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import encoding from 'k6/encoding';

// Custom metrics
const errorRate = new Rate('errors');
const authSuccessRate = new Rate('auth_success');
const trustLevelRate = new Rate('trust_level_high');

// Test configuration
const BASE_URL = __ENV.BASE_URL || 'https://api.yourdomain.com';
const KEYCLOAK_URL = __ENV.KEYCLOAK_URL || 'https://auth.yourdomain.com';

// Load test users from file
const users = new SharedArray('users', function() {
  return JSON.parse(open('./test-users.json'));
});

// Test scenarios for different load patterns
export const options = {
  scenarios: {
    // Scenario 1: Steady load
    steady_load: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 50,
      maxVUs: 100,
    },
    // Scenario 2: Ramp up/down
    ramp_up_down: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 200,
      stages: [
        { duration: '2m', target: 100 },
        { duration: '5m', target: 100 },
        { duration: '2m', target: 200 },
        { duration: '5m', target: 200 },
        { duration: '2m', target: 100 },
        { duration: '2m', target: 10 },
      ],
    },
    // Scenario 3: Spike test
    spike_test: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 500,
      stages: [
        { duration: '1m', target: 10 },
        { duration: '30s', target: 500 },
        { duration: '3m', target: 500 },
        { duration: '30s', target: 10 },
        { duration: '1m', target: 10 },
      ],
    },
    // Scenario 4: Stress test
    stress_test: {
      executor: 'ramping-arrival-rate',
      startRate: 50,
      timeUnit: '1s',
      preAllocatedVUs: 100,
      maxVUs: 1000,
      stages: [
        { duration: '5m', target: 200 },
        { duration: '5m', target: 400 },
        { duration: '5m', target: 600 },
        { duration: '5m', target: 800 },
        { duration: '5m', target: 1000 },
        { duration: '5m', target: 50 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // 95% of requests under 500ms
    http_req_failed: ['rate<0.01'], // Error rate under 1%
    errors: ['rate<0.01'], // Custom error rate under 1%
    auth_success: ['rate>0.95'], // Auth success rate above 95%
  },
};

// Setup function - runs once before the test
export function setup() {
  console.log('Setting up load test...');
  
  // Verify services are healthy
  const healthChecks = [
    { name: 'API', url: `${BASE_URL}/health` },
    { name: 'Keycloak', url: `${KEYCLOAK_URL}/realms/zero-trust` },
  ];

  healthChecks.forEach(service => {
    const res = http.get(service.url);
    if (res.status !== 200) {
      throw new Error(`${service.name} health check failed: ${res.status}`);
    }
  });

  return { startTime: Date.now() };
}

// Main test function - runs for each VU iteration
export default function(data) {
  // Select random user
  const user = users[Math.floor(Math.random() * users.length)];
  
  // Test flow based on weighted scenarios
  const scenario = selectScenario();
  
  switch(scenario) {
    case 'login_flow':
      testLoginFlow(user);
      break;
    case 'api_requests':
      testAPIRequests(user);
      break;
    case 'high_trust_operations':
      testHighTrustOperations(user);
      break;
    case 'compliance_operations':
      testComplianceOperations(user);
      break;
    default:
      testLoginFlow(user);
  }
  
  sleep(Math.random() * 2 + 1); // Random think time between 1-3 seconds
}

// Test login flow
function testLoginFlow(user) {
  const loginPayload = {
    username: user.username,
    password: user.password,
    grant_type: 'password',
    client_id: 'zero-trust-app',
    client_secret: __ENV.CLIENT_SECRET || 'test-secret',
  };

  const loginParams = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    tags: { name: 'login' },
  };

  // Perform login
  const loginRes = http.post(
    `${KEYCLOAK_URL}/realms/zero-trust/protocol/openid-connect/token`,
    loginPayload,
    loginParams
  );

  const loginSuccess = check(loginRes, {
    'login successful': (r) => r.status === 200,
    'access token present': (r) => r.json('access_token') !== undefined,
  });

  errorRate.add(!loginSuccess);
  authSuccessRate.add(loginSuccess);

  if (loginSuccess) {
    const token = loginRes.json('access_token');
    
    // Test authenticated endpoints
    const authParams = {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
      tags: { name: 'authenticated_request' },
    };

    // Get user profile
    const profileRes = http.get(`${BASE_URL}/api/profile`, authParams);
    check(profileRes, {
      'profile retrieved': (r) => r.status === 200,
      'trust level present': (r) => r.json('trust_level') !== undefined,
    });

    // Track trust levels
    if (profileRes.status === 200) {
      const trustLevel = profileRes.json('trust_level');
      trustLevelRate.add(trustLevel >= 75);
    }
  }
}

// Test API requests with varying trust levels
function testAPIRequests(user) {
  const token = getAuthToken(user);
  if (!token) return;

  const authParams = {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  };

  // Test endpoints based on user trust level
  const endpoints = [
    { path: '/api/dashboard', minTrust: 25, tag: 'low_trust' },
    { path: '/api/secure/data', minTrust: 50, tag: 'medium_trust' },
    { path: '/api/admin/users', minTrust: 75, tag: 'high_trust' },
    { path: '/api/financial/transactions', minTrust: 100, tag: 'full_trust' },
  ];

  endpoints.forEach(endpoint => {
    const params = Object.assign({}, authParams, {
      tags: { name: endpoint.tag },
    });

    const res = http.get(`${BASE_URL}${endpoint.path}`, params);
    
    const expectedStatus = user.trustLevel >= endpoint.minTrust ? 200 : 403;
    check(res, {
      [`${endpoint.tag} access correct`]: (r) => r.status === expectedStatus,
    });
  });
}

// Test high trust operations
function testHighTrustOperations(user) {
  const token = getAuthToken(user);
  if (!token || user.trustLevel < 75) return;

  const authParams = {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    tags: { name: 'high_trust_operation' },
  };

  // Admin operations
  const adminOps = [
    {
      method: 'GET',
      path: '/api/admin/audit-logs',
      body: null,
    },
    {
      method: 'POST',
      path: '/api/admin/users/roles',
      body: JSON.stringify({
        userId: 'test-user-123',
        roles: ['user', 'analyst'],
      }),
    },
    {
      method: 'PUT',
      path: '/api/admin/config',
      body: JSON.stringify({
        setting: 'trust_level_enforcement',
        value: 'strict',
      }),
    },
  ];

  adminOps.forEach(op => {
    const res = op.method === 'GET' 
      ? http.get(`${BASE_URL}${op.path}`, authParams)
      : http[op.method.toLowerCase()](`${BASE_URL}${op.path}`, op.body, authParams);
    
    check(res, {
      [`${op.method} ${op.path} successful`]: (r) => r.status === 200 || r.status === 201,
    });
  });
}

// Test compliance-related operations
function testComplianceOperations(user) {
  const token = getAuthToken(user);
  if (!token) return;

  const authParams = {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  };

  // GDPR data access with purpose
  const gdprParams = Object.assign({}, authParams, {
    tags: { name: 'gdpr_compliance' },
  });

  const gdprRes = http.get(
    `${BASE_URL}/api/personal-data?purpose=service_provision&fields=name,email`,
    gdprParams
  );

  check(gdprRes, {
    'GDPR compliant access': (r) => {
      if (r.status !== 200) return false;
      const body = r.json();
      return body.purpose_recorded === true && body.audit_logged === true;
    },
  });

  // Test data without purpose (should fail)
  const noPurposeRes = http.get(
    `${BASE_URL}/api/personal-data?fields=name,email`,
    authParams
  );

  check(noPurposeRes, {
    'GDPR non-compliant rejected': (r) => r.status === 400,
  });
}

// Helper function to get auth token
function getAuthToken(user) {
  const loginPayload = {
    username: user.username,
    password: user.password,
    grant_type: 'password',
    client_id: 'zero-trust-app',
    client_secret: __ENV.CLIENT_SECRET || 'test-secret',
  };

  const loginRes = http.post(
    `${KEYCLOAK_URL}/realms/zero-trust/protocol/openid-connect/token`,
    loginPayload,
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  if (loginRes.status === 200) {
    return loginRes.json('access_token');
  }
  return null;
}

// Select scenario based on weights
function selectScenario() {
  const scenarios = [
    { name: 'login_flow', weight: 30 },
    { name: 'api_requests', weight: 50 },
    { name: 'high_trust_operations', weight: 15 },
    { name: 'compliance_operations', weight: 5 },
  ];

  const totalWeight = scenarios.reduce((sum, s) => sum + s.weight, 0);
  let random = Math.random() * totalWeight;

  for (const scenario of scenarios) {
    random -= scenario.weight;
    if (random <= 0) {
      return scenario.name;
    }
  }

  return scenarios[0].name;
}

// Teardown function - runs once after the test
export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Load test completed in ${duration} seconds`);
}