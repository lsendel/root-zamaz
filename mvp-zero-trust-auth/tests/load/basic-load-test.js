import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Define custom metrics
const httpRequestDuration = new Rate('http_req_duration');
const httpRequestFailed = new Rate('http_req_failed');

export const options = {
  vus: 5, // 5 virtual users
  duration: '10s', // for 10 seconds
  thresholds: {
    // http errors should be less than 1%
    'http_req_failed': ['rate<0.01'],
    // 95% of requests should be below 200ms
    'http_req_duration': ['p(95)<200'],
  },
};

export default function () {
  // Using a publicly available test API as a placeholder
  const res = http.get('https://jsonplaceholder.typicode.com/todos/1');

  // Add custom metrics
  httpRequestDuration.add(res.timings.duration);
  httpRequestFailed.add(res.status !== 200);

  // Check for response status
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response body is not empty': (r) => r.body.length > 0,
  });

  // Simulate think time
  sleep(1);
}
