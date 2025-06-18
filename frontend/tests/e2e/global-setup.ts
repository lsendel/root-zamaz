import { chromium, FullConfig } from '@playwright/test';
import { execSync } from 'child_process';
import { mkdir } from 'fs/promises';

async function globalSetup(config: FullConfig) {
  console.log('🚀 Starting global setup...');
  
  // Create test results directory
  try {
    await mkdir('test-results', { recursive: true });
    await mkdir('test-results/screenshots', { recursive: true });
  } catch (error) {
    // Directory might already exist
  }
  
  // Wait for backend to be ready
  console.log('⏳ Waiting for backend to be ready...');
  const apiUrl = process.env.API_URL || 'http://localhost:8080';
  
  const browser = await chromium.launch();
  const page = await browser.newPage();
  
  let backendReady = false;
  let attempts = 0;
  const maxAttempts = 30;
  
  while (!backendReady && attempts < maxAttempts) {
    try {
      const response = await page.goto(`${apiUrl}/health`, { timeout: 5000 });
      if (response && response.status() === 200) {
        backendReady = true;
        console.log('✅ Backend is ready!');
      }
    } catch (error) {
      attempts++;
      console.log(`⏳ Attempt ${attempts}/${maxAttempts} - Backend not ready yet...`);
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
  
  if (!backendReady) {
    console.error('❌ Backend failed to become ready in time');
    throw new Error('Backend is not ready for testing');
  }
  
  // Verify admin user exists
  try {
    const loginResponse = await page.request.post(`${apiUrl}/api/auth/login`, {
      data: {
        username: 'admin',
        password: 'password'
      }
    });
    
    if (loginResponse.status() !== 200) {
      console.error('❌ Admin user login failed');
      const responseText = await loginResponse.text();
      console.error('Response:', responseText);
    } else {
      console.log('✅ Admin user verified');
    }
  } catch (error) {
    console.error('❌ Failed to verify admin user:', error);
  }
  
  await browser.close();
  
  console.log('✅ Global setup completed');
}

export default globalSetup;