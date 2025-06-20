// API Configuration with environment-based settings and health checking
declare global {
  const __BACKEND_URL__: string
  const __DEV_MODE__: boolean
}

interface ApiConfig {
  baseURL: string
  timeout: number
  retries: number
  healthCheckPath: string
}

interface HealthStatus {
  healthy: boolean
  latency?: number
  error?: string
  lastCheck: Date
}

class ApiConfigService {
  private config: ApiConfig
  private healthStatus: HealthStatus = {
    healthy: false,
    lastCheck: new Date()
  }

  constructor() {
    this.config = this.detectApiConfig()
    this.logConfiguration()
  }

  private detectApiConfig(): ApiConfig {
    // Development: Use Vite proxy or direct backend URL
    if (this.isDevelopment()) {
      const backendUrl = typeof __BACKEND_URL__ !== 'undefined' ? __BACKEND_URL__ : 'http://localhost:3001'
      
      return {
        baseURL: this.shouldUseProxy() ? '/api' : `${backendUrl}/api`,
        timeout: 10000,
        retries: 3,
        healthCheckPath: '/health'
      }
    }

    // Production: Use relative paths (assumes same origin) or environment variables
    const productionBaseUrl = import.meta.env.VITE_API_BASE_URL || '/api'
    
    return {
      baseURL: productionBaseUrl,
      timeout: 15000,
      retries: 2,
      healthCheckPath: '/health'
    }
  }

  private isDevelopment(): boolean {
    return (
      import.meta.env.DEV || 
      typeof __DEV_MODE__ !== 'undefined' && __DEV_MODE__ ||
      import.meta.env.MODE === 'development'
    )
  }

  private shouldUseProxy(): boolean {
    // Use proxy when running on Vite dev server (localhost:5173)
    return (
      this.isDevelopment() && 
      window.location.hostname === 'localhost' && 
      window.location.port === '5173'
    )
  }

  private logConfiguration(): void {
    console.group('🔧 API Configuration')
    console.log('Mode:', this.isDevelopment() ? 'Development' : 'Production')
    console.log('Base URL:', this.config.baseURL)
    console.log('Use Proxy:', this.shouldUseProxy())
    console.log('Timeout:', this.config.timeout)
    console.log('Retries:', this.config.retries)
    if (this.isDevelopment()) {
      console.log('Backend URL:', typeof __BACKEND_URL__ !== 'undefined' ? __BACKEND_URL__ : 'Not defined')
    }
    console.groupEnd()
  }

  getConfig(): ApiConfig {
    return { ...this.config }
  }

  async checkHealth(): Promise<HealthStatus> {
    const startTime = performance.now()
    
    try {
      const response = await fetch(`${this.config.baseURL}${this.config.healthCheckPath}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(5000)
      })

      const latency = Math.round(performance.now() - startTime)
      
      if (response.ok) {
        this.healthStatus = {
          healthy: true,
          latency,
          lastCheck: new Date()
        }
        console.log(`✅ API Health Check: OK (${latency}ms)`)
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
    } catch (error) {
      const latency = Math.round(performance.now() - startTime)
      this.healthStatus = {
        healthy: false,
        latency,
        error: error instanceof Error ? error.message : 'Unknown error',
        lastCheck: new Date()
      }
      console.warn(`❌ API Health Check Failed (${latency}ms):`, this.healthStatus.error)
    }

    return this.healthStatus
  }

  getHealthStatus(): HealthStatus {
    return { ...this.healthStatus }
  }

  async waitForHealthy(timeoutMs: number = 30000): Promise<boolean> {
    const startTime = Date.now()
    
    while (Date.now() - startTime < timeoutMs) {
      const health = await this.checkHealth()
      
      if (health.healthy) {
        return true
      }
      
      // Wait before retrying
      await new Promise(resolve => setTimeout(resolve, 1000))
    }
    
    return false
  }

  // Helper method to get the full URL for a given endpoint
  getFullUrl(endpoint: string): string {
    const base = this.config.baseURL
    const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`
    
    // If baseURL is relative, make it absolute
    if (base.startsWith('/')) {
      return `${window.location.origin}${base}${path}`
    }
    
    return `${base}${path}`
  }
}

// Export singleton instance
export const apiConfig = new ApiConfigService()

// Export types for use in other files
export type { ApiConfig, HealthStatus }