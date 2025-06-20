// Service Discovery Configuration for Kubernetes environments
import { apiConfig } from './api'

interface ServiceEndpoint {
  name: string
  host: string
  port: number
  protocol: 'http' | 'https'
  path?: string
  priority?: number
  healthy?: boolean
  lastCheck?: Date
}

interface DiscoveryConfig {
  provider: 'kubernetes' | 'consul' | 'static' | 'dns'
  namespace?: string
  serviceName?: string
  endpoints: ServiceEndpoint[]
  healthCheckInterval?: number
  fallbackEnabled?: boolean
}

interface ServiceDiscoveryOptions {
  timeout?: number
  retries?: number
  healthCheck?: boolean
  loadBalancer?: 'round-robin' | 'random' | 'least-connections'
}

class ServiceDiscovery {
  private config: DiscoveryConfig
  private currentEndpointIndex = 0
  private healthCheckTimers: Map<string, NodeJS.Timeout> = new Map()
  
  constructor() {
    this.config = this.detectDiscoveryConfig()
    this.logConfiguration()
    
    if (this.config.healthCheckInterval) {
      this.startHealthChecks()
    }
  }

  private detectDiscoveryConfig(): DiscoveryConfig {
    // Check if running in Kubernetes (via environment variables or DNS)
    if (this.isKubernetesEnvironment()) {
      return {
        provider: 'kubernetes',
        namespace: this.getKubernetesNamespace(),
        serviceName: 'zamaz-api-service',
        endpoints: this.getKubernetesEndpoints(),
        healthCheckInterval: 30000, // 30 seconds
        fallbackEnabled: true
      }
    }

    // Check if Consul is available
    if (this.isConsulAvailable()) {
      return {
        provider: 'consul',
        endpoints: this.getConsulEndpoints(),
        healthCheckInterval: 10000, // 10 seconds
        fallbackEnabled: true
      }
    }

    // Fall back to static configuration
    return {
      provider: 'static',
      endpoints: this.getStaticEndpoints(),
      healthCheckInterval: 60000, // 1 minute
      fallbackEnabled: false
    }
  }

  private isKubernetesEnvironment(): boolean {
    // Check for Kubernetes service environment variables
    const k8sServiceHost = import.meta.env.VITE_KUBERNETES_SERVICE_HOST
    const k8sNamespace = import.meta.env.VITE_K8S_NAMESPACE
    
    // Check if running in a pod (mounted service account)
    const inCluster = window.location.hostname.includes('.cluster.local') ||
                     window.location.hostname.includes('.svc') ||
                     !!k8sServiceHost ||
                     !!k8sNamespace

    return inCluster
  }

  private getKubernetesNamespace(): string {
    return import.meta.env.VITE_K8S_NAMESPACE || 
           import.meta.env.VITE_POD_NAMESPACE || 
           'zamaz'
  }

  private getKubernetesEndpoints(): ServiceEndpoint[] {
    const namespace = this.getKubernetesNamespace()
    const serviceName = import.meta.env.VITE_API_SERVICE_NAME || 'zamaz-api-service'
    
    // Kubernetes DNS patterns
    const endpoints: ServiceEndpoint[] = [
      {
        name: 'k8s-service-dns',
        host: `${serviceName}.${namespace}.svc.cluster.local`,
        port: 8080,
        protocol: 'http',
        priority: 1
      },
      {
        name: 'k8s-service-short',
        host: `${serviceName}.${namespace}`,
        port: 8080,
        protocol: 'http',
        priority: 2
      }
    ]

    // Add headless service endpoints if available
    const headlessService = import.meta.env.VITE_HEADLESS_SERVICE
    if (headlessService) {
      endpoints.push({
        name: 'k8s-headless',
        host: `${headlessService}.${namespace}.svc.cluster.local`,
        port: 8080,
        protocol: 'http',
        priority: 3
      })
    }

    // Add specific pod endpoints if provided
    const podEndpoints = import.meta.env.VITE_POD_ENDPOINTS
    if (podEndpoints) {
      const pods = podEndpoints.split(',')
      pods.forEach((pod: string, index: number) => {
        endpoints.push({
          name: `k8s-pod-${index}`,
          host: pod.trim(),
          port: 8080,
          protocol: 'http',
          priority: 10 + index
        })
      })
    }

    return endpoints
  }

  private isConsulAvailable(): boolean {
    // Check if Consul DNS or API is configured
    const consulHost = import.meta.env.VITE_CONSUL_HOST
    const consulEnabled = import.meta.env.VITE_CONSUL_ENABLED === 'true'
    
    return !!consulHost || consulEnabled
  }

  private getConsulEndpoints(): ServiceEndpoint[] {
    const consulHost = import.meta.env.VITE_CONSUL_HOST || 'consul.service.consul'
    const serviceName = import.meta.env.VITE_API_SERVICE_NAME || 'zamaz-api'
    
    return [
      {
        name: 'consul-service',
        host: `${serviceName}.service.consul`,
        port: 8080,
        protocol: 'http',
        priority: 1
      }
    ]
  }

  private getStaticEndpoints(): ServiceEndpoint[] {
    const endpoints: ServiceEndpoint[] = []
    
    // Development endpoints
    if (import.meta.env.DEV) {
      endpoints.push({
        name: 'dev-local',
        host: 'localhost',
        port: 3001,
        protocol: 'http',
        priority: 1
      })
    }

    // Production endpoints from environment
    const apiHost = import.meta.env.VITE_API_HOST
    if (apiHost) {
      endpoints.push({
        name: 'env-api-host',
        host: apiHost,
        port: parseInt(import.meta.env.VITE_API_PORT || '443'),
        protocol: import.meta.env.VITE_API_PROTOCOL as 'http' | 'https' || 'https',
        priority: 1
      })
    }

    // Default fallback
    if (endpoints.length === 0) {
      endpoints.push({
        name: 'default',
        host: window.location.hostname,
        port: window.location.port ? parseInt(window.location.port) : 
              window.location.protocol === 'https:' ? 443 : 80,
        protocol: window.location.protocol.replace(':', '') as 'http' | 'https',
        priority: 10
      })
    }

    return endpoints
  }

  private logConfiguration(): void {
    console.group('🔍 Service Discovery Configuration')
    console.log('Provider:', this.config.provider)
    console.log('Namespace:', this.config.namespace || 'N/A')
    console.log('Service Name:', this.config.serviceName || 'N/A')
    console.log('Endpoints:', this.config.endpoints)
    console.log('Health Check Interval:', this.config.healthCheckInterval || 'Disabled')
    console.log('Fallback Enabled:', this.config.fallbackEnabled)
    console.groupEnd()
  }

  private startHealthChecks(): void {
    if (!this.config.healthCheckInterval) return

    this.config.endpoints.forEach(endpoint => {
      // Initial health check
      this.checkEndpointHealth(endpoint)

      // Schedule periodic health checks
      const timer = setInterval(() => {
        this.checkEndpointHealth(endpoint)
      }, this.config.healthCheckInterval!)

      this.healthCheckTimers.set(endpoint.name, timer)
    })
  }

  private async checkEndpointHealth(endpoint: ServiceEndpoint): Promise<void> {
    const url = `${endpoint.protocol}://${endpoint.host}:${endpoint.port}/health`
    const startTime = performance.now()

    try {
      const response = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
        mode: 'cors',
        credentials: 'omit'
      })

      const latency = Math.round(performance.now() - startTime)
      endpoint.healthy = response.ok
      endpoint.lastCheck = new Date()

      console.log(`🏥 Health check for ${endpoint.name}: ${endpoint.healthy ? '✅' : '❌'} (${latency}ms)`)
    } catch (error) {
      endpoint.healthy = false
      endpoint.lastCheck = new Date()
      console.warn(`🏥 Health check failed for ${endpoint.name}:`, error)
    }
  }

  // Get the next available endpoint using the configured load balancer
  getNextEndpoint(options?: ServiceDiscoveryOptions): ServiceEndpoint | null {
    const healthyEndpoints = this.config.endpoints
      .filter(ep => options?.healthCheck ? ep.healthy !== false : true)
      .sort((a, b) => (a.priority || 999) - (b.priority || 999))

    if (healthyEndpoints.length === 0) {
      console.warn('No healthy endpoints available')
      return this.config.fallbackEnabled ? this.config.endpoints[0] : null
    }

    const strategy = options?.loadBalancer || 'round-robin'

    switch (strategy) {
      case 'round-robin':
        const endpoint = healthyEndpoints[this.currentEndpointIndex % healthyEndpoints.length]
        this.currentEndpointIndex++
        return endpoint

      case 'random':
        return healthyEndpoints[Math.floor(Math.random() * healthyEndpoints.length)]

      case 'least-connections':
        // For client-side, we can't track real connections, so fall back to round-robin
        return healthyEndpoints[0]

      default:
        return healthyEndpoints[0]
    }
  }

  // Build the base URL for API calls
  buildApiUrl(options?: ServiceDiscoveryOptions): string {
    const endpoint = this.getNextEndpoint(options)
    
    if (!endpoint) {
      console.error('No endpoint available, falling back to default API config')
      return apiConfig.getConfig().baseURL
    }

    const baseUrl = `${endpoint.protocol}://${endpoint.host}:${endpoint.port}`
    const path = endpoint.path || '/api'
    
    return `${baseUrl}${path}`
  }

  // Get all healthy endpoints
  getHealthyEndpoints(): ServiceEndpoint[] {
    return this.config.endpoints.filter(ep => ep.healthy !== false)
  }

  // Manually trigger health checks
  async refreshHealth(): Promise<void> {
    const promises = this.config.endpoints.map(ep => this.checkEndpointHealth(ep))
    await Promise.all(promises)
  }

  // Clean up health check timers
  destroy(): void {
    this.healthCheckTimers.forEach(timer => clearInterval(timer))
    this.healthCheckTimers.clear()
  }

  // Update configuration dynamically (e.g., from service discovery API)
  updateEndpoints(endpoints: ServiceEndpoint[]): void {
    this.config.endpoints = endpoints
    console.log('📍 Service endpoints updated:', endpoints)
    
    // Restart health checks with new endpoints
    this.destroy()
    if (this.config.healthCheckInterval) {
      this.startHealthChecks()
    }
  }

  // Integration with Consul API
  async fetchConsulEndpoints(serviceName: string): Promise<ServiceEndpoint[]> {
    const consulUrl = import.meta.env.VITE_CONSUL_API_URL || 'http://localhost:8500'
    
    try {
      const response = await fetch(`${consulUrl}/v1/health/service/${serviceName}?passing=true`)
      const services = await response.json()
      
      return services.map((service: any, index: number) => ({
        name: `consul-${service.Service.ID}`,
        host: service.Service.Address || service.Node.Address,
        port: service.Service.Port,
        protocol: 'http' as const,
        priority: index + 1,
        healthy: true
      }))
    } catch (error) {
      console.error('Failed to fetch Consul endpoints:', error)
      return []
    }
  }

  // Integration with Kubernetes API
  async fetchKubernetesEndpoints(namespace: string, serviceName: string): Promise<ServiceEndpoint[]> {
    // In a real implementation, this would call the Kubernetes API
    // For browser-based apps, this typically requires a proxy or backend endpoint
    const k8sApiUrl = import.meta.env.VITE_K8S_API_URL
    
    if (!k8sApiUrl) {
      console.warn('Kubernetes API URL not configured')
      return []
    }

    try {
      const response = await fetch(
        `${k8sApiUrl}/api/v1/namespaces/${namespace}/endpoints/${serviceName}`,
        {
          headers: {
            'Authorization': `Bearer ${import.meta.env.VITE_K8S_TOKEN || ''}`
          }
        }
      )
      
      const data = await response.json()
      const endpoints: ServiceEndpoint[] = []
      
      data.subsets?.forEach((subset: any) => {
        subset.addresses?.forEach((address: any, index: number) => {
          subset.ports?.forEach((port: any) => {
            endpoints.push({
              name: `k8s-${address.targetRef?.name || address.ip}`,
              host: address.ip,
              port: port.port,
              protocol: port.name === 'https' ? 'https' : 'http',
              priority: index + 1,
              healthy: true
            })
          })
        })
      })
      
      return endpoints
    } catch (error) {
      console.error('Failed to fetch Kubernetes endpoints:', error)
      return []
    }
  }
}

// Export singleton instance
export const serviceDiscovery = new ServiceDiscovery()

// Export types
export type { ServiceEndpoint, DiscoveryConfig, ServiceDiscoveryOptions }

// Helper function to integrate with existing API configuration
export function getDiscoveryAwareApiUrl(): string {
  const discoveryUrl = serviceDiscovery.buildApiUrl({ healthCheck: true })
  
  // If discovery returns a valid URL, use it
  if (discoveryUrl && !discoveryUrl.includes('undefined')) {
    return discoveryUrl
  }
  
  // Fall back to the original API config
  return apiConfig.getConfig().baseURL
}