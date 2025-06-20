package loadbalancer

import (
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mvp-zero-trust-auth/pkg/discovery"
)

// LoadBalancer defines the interface for load balancing strategies
type LoadBalancer interface {
	// Select chooses a service instance based on the strategy
	Select(services []*discovery.Service, request *Request) (*discovery.Service, error)
	
	// UpdateHealth updates the health status of a service instance
	UpdateHealth(serviceID string, health discovery.HealthStatus)
	
	// GetStats returns statistics about the load balancer
	GetStats() map[string]interface{}
	
	// Reset resets the load balancer state
	Reset()
}

// Request represents an incoming request with metadata for load balancing decisions
type Request struct {
	ID          string            `json:"id"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	ClientIP    string            `json:"client_ip"`
	UserID      string            `json:"user_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// Strategy represents different load balancing strategies
type Strategy string

const (
	StrategyRoundRobin       Strategy = "round_robin"
	StrategyWeightedRoundRobin Strategy = "weighted_round_robin"
	StrategyLeastConnections Strategy = "least_connections"
	StrategyRandom           Strategy = "random"
	StrategyWeightedRandom   Strategy = "weighted_random"
	StrategyConsistentHash   Strategy = "consistent_hash"
	StrategyIPHash           Strategy = "ip_hash"
	StrategyLeastResponseTime Strategy = "least_response_time"
)

// Config holds load balancer configuration
type Config struct {
	Strategy              Strategy      `env:"LB_STRATEGY" default:"round_robin"`
	HealthyOnly           bool          `env:"LB_HEALTHY_ONLY" default:"true"`
	MaxRetries            int           `env:"LB_MAX_RETRIES" default:"3"`
	RetryDelay            time.Duration `env:"LB_RETRY_DELAY" default:"100ms"`
	CircuitBreakerEnabled bool          `env:"LB_CIRCUIT_BREAKER" default:"true"`
	CircuitBreakerThreshold int         `env:"LB_CB_THRESHOLD" default:"5"`
	CircuitBreakerTimeout time.Duration `env:"LB_CB_TIMEOUT" default:"30s"`
}

// RoundRobinBalancer implements round-robin load balancing
type RoundRobinBalancer struct {
	counter uint64
	mutex   sync.RWMutex
	stats   map[string]int64
}

// NewRoundRobinBalancer creates a new round-robin load balancer
func NewRoundRobinBalancer() *RoundRobinBalancer {
	return &RoundRobinBalancer{
		stats: make(map[string]int64),
	}
}

// Select implements round-robin selection
func (r *RoundRobinBalancer) Select(services []*discovery.Service, request *Request) (*discovery.Service, error) {
	healthyServices := filterHealthyServices(services)
	if len(healthyServices) == 0 {
		return nil, fmt.Errorf("no healthy services available")
	}

	index := atomic.AddUint64(&r.counter, 1) % uint64(len(healthyServices))
	selected := healthyServices[index]

	r.mutex.Lock()
	r.stats[selected.ID]++
	r.mutex.Unlock()

	return selected, nil
}

// UpdateHealth is a no-op for round-robin
func (r *RoundRobinBalancer) UpdateHealth(serviceID string, health discovery.HealthStatus) {
	// Round-robin doesn't need to track health separately
}

// GetStats returns selection statistics
func (r *RoundRobinBalancer) GetStats() map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	
	stats := make(map[string]interface{})
	stats["strategy"] = "round_robin"
	stats["selections"] = make(map[string]int64)
	
	for serviceID, count := range r.stats {
		stats["selections"].(map[string]int64)[serviceID] = count
	}
	
	return stats
}

// Reset resets the balancer state
func (r *RoundRobinBalancer) Reset() {
	atomic.StoreUint64(&r.counter, 0)
	r.mutex.Lock()
	r.stats = make(map[string]int64)
	r.mutex.Unlock()
}

// WeightedRoundRobinBalancer implements weighted round-robin load balancing
type WeightedRoundRobinBalancer struct {
	weights map[string]int
	current map[string]int
	total   int
	mutex   sync.RWMutex
	stats   map[string]int64
}

// NewWeightedRoundRobinBalancer creates a new weighted round-robin load balancer
func NewWeightedRoundRobinBalancer(weights map[string]int) *WeightedRoundRobinBalancer {
	current := make(map[string]int)
	total := 0
	
	for serviceID, weight := range weights {
		current[serviceID] = 0
		total += weight
	}

	return &WeightedRoundRobinBalancer{
		weights: weights,
		current: current,
		total:   total,
		stats:   make(map[string]int64),
	}
}

// Select implements weighted round-robin selection
func (w *WeightedRoundRobinBalancer) Select(services []*discovery.Service, request *Request) (*discovery.Service, error) {
	healthyServices := filterHealthyServices(services)
	if len(healthyServices) == 0 {
		return nil, fmt.Errorf("no healthy services available")
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	var selected *discovery.Service
	maxCurrentWeight := -1

	for _, service := range healthyServices {
		weight, exists := w.weights[service.ID]
		if !exists {
			weight = 1 // Default weight
		}

		w.current[service.ID] += weight
		if w.current[service.ID] > maxCurrentWeight {
			maxCurrentWeight = w.current[service.ID]
			selected = service
		}
	}

	if selected != nil {
		w.current[selected.ID] -= w.total
		w.stats[selected.ID]++
	}

	return selected, nil
}

// UpdateHealth is a no-op for weighted round-robin
func (w *WeightedRoundRobinBalancer) UpdateHealth(serviceID string, health discovery.HealthStatus) {
	// Weighted round-robin doesn't need to track health separately
}

// GetStats returns selection statistics
func (w *WeightedRoundRobinBalancer) GetStats() map[string]interface{} {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	
	stats := make(map[string]interface{})
	stats["strategy"] = "weighted_round_robin"
	stats["weights"] = w.weights
	stats["current"] = w.current
	stats["selections"] = make(map[string]int64)
	
	for serviceID, count := range w.stats {
		stats["selections"].(map[string]int64)[serviceID] = count
	}
	
	return stats
}

// Reset resets the balancer state
func (w *WeightedRoundRobinBalancer) Reset() {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	
	for serviceID := range w.current {
		w.current[serviceID] = 0
	}
	w.stats = make(map[string]int64)
}

// RandomBalancer implements random load balancing
type RandomBalancer struct {
	rand  *rand.Rand
	mutex sync.RWMutex
	stats map[string]int64
}

// NewRandomBalancer creates a new random load balancer
func NewRandomBalancer() *RandomBalancer {
	return &RandomBalancer{
		rand:  rand.New(rand.NewSource(time.Now().UnixNano())),
		stats: make(map[string]int64),
	}
}

// Select implements random selection
func (r *RandomBalancer) Select(services []*discovery.Service, request *Request) (*discovery.Service, error) {
	healthyServices := filterHealthyServices(services)
	if len(healthyServices) == 0 {
		return nil, fmt.Errorf("no healthy services available")
	}

	r.mutex.Lock()
	index := r.rand.Intn(len(healthyServices))
	selected := healthyServices[index]
	r.stats[selected.ID]++
	r.mutex.Unlock()

	return selected, nil
}

// UpdateHealth is a no-op for random
func (r *RandomBalancer) UpdateHealth(serviceID string, health discovery.HealthStatus) {
	// Random doesn't need to track health separately
}

// GetStats returns selection statistics
func (r *RandomBalancer) GetStats() map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	
	stats := make(map[string]interface{})
	stats["strategy"] = "random"
	stats["selections"] = make(map[string]int64)
	
	for serviceID, count := range r.stats {
		stats["selections"].(map[string]int64)[serviceID] = count
	}
	
	return stats
}

// Reset resets the balancer state
func (r *RandomBalancer) Reset() {
	r.mutex.Lock()
	r.stats = make(map[string]int64)
	r.mutex.Unlock()
}

// ConsistentHashBalancer implements consistent hashing
type ConsistentHashBalancer struct {
	hash       map[uint32]string // hash -> service ID
	sortedKeys []uint32
	replicas   int
	mutex      sync.RWMutex
	stats      map[string]int64
}

// NewConsistentHashBalancer creates a new consistent hash load balancer
func NewConsistentHashBalancer(replicas int) *ConsistentHashBalancer {
	return &ConsistentHashBalancer{
		hash:     make(map[uint32]string),
		replicas: replicas,
		stats:    make(map[string]int64),
	}
}

// Select implements consistent hash selection
func (c *ConsistentHashBalancer) Select(services []*discovery.Service, request *Request) (*discovery.Service, error) {
	healthyServices := filterHealthyServices(services)
	if len(healthyServices) == 0 {
		return nil, fmt.Errorf("no healthy services available")
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Update hash ring
	c.updateHashRing(healthyServices)

	// Hash the request key (using client IP or session ID)
	key := request.ClientIP
	if request.SessionID != "" {
		key = request.SessionID
	}

	hash := c.hashKey(key)
	serviceID := c.getService(hash)
	
	// Find the actual service
	var selected *discovery.Service
	for _, service := range healthyServices {
		if service.ID == serviceID {
			selected = service
			break
		}
	}

	if selected != nil {
		c.stats[selected.ID]++
	}

	return selected, nil
}

// UpdateHealth updates the hash ring when service health changes
func (c *ConsistentHashBalancer) UpdateHealth(serviceID string, health discovery.HealthStatus) {
	// Consistent hash will rebuild the ring on next selection
}

// GetStats returns selection statistics
func (c *ConsistentHashBalancer) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	stats := make(map[string]interface{})
	stats["strategy"] = "consistent_hash"
	stats["replicas"] = c.replicas
	stats["ring_size"] = len(c.hash)
	stats["selections"] = make(map[string]int64)
	
	for serviceID, count := range c.stats {
		stats["selections"].(map[string]int64)[serviceID] = count
	}
	
	return stats
}

// Reset resets the balancer state
func (c *ConsistentHashBalancer) Reset() {
	c.mutex.Lock()
	c.hash = make(map[uint32]string)
	c.sortedKeys = nil
	c.stats = make(map[string]int64)
	c.mutex.Unlock()
}

// updateHashRing rebuilds the hash ring with current services
func (c *ConsistentHashBalancer) updateHashRing(services []*discovery.Service) {
	c.hash = make(map[uint32]string)
	
	for _, service := range services {
		for i := 0; i < c.replicas; i++ {
			key := fmt.Sprintf("%s:%d", service.ID, i)
			hash := c.hashKey(key)
			c.hash[hash] = service.ID
		}
	}
	
	// Sort keys for binary search
	c.sortedKeys = make([]uint32, 0, len(c.hash))
	for k := range c.hash {
		c.sortedKeys = append(c.sortedKeys, k)
	}
	sort.Slice(c.sortedKeys, func(i, j int) bool {
		return c.sortedKeys[i] < c.sortedKeys[j]
	})
}

// hashKey creates a hash for a given key
func (c *ConsistentHashBalancer) hashKey(key string) uint32 {
	return crc32.ChecksumIEEE([]byte(key))
}

// getService finds the service for a given hash
func (c *ConsistentHashBalancer) getService(hash uint32) string {
	if len(c.sortedKeys) == 0 {
		return ""
	}
	
	// Binary search for the first key >= hash
	idx := sort.Search(len(c.sortedKeys), func(i int) bool {
		return c.sortedKeys[i] >= hash
	})
	
	// Wrap around if necessary
	if idx == len(c.sortedKeys) {
		idx = 0
	}
	
	return c.hash[c.sortedKeys[idx]]
}

// IPHashBalancer implements IP-based hash load balancing
type IPHashBalancer struct {
	mutex sync.RWMutex
	stats map[string]int64
}

// NewIPHashBalancer creates a new IP hash load balancer
func NewIPHashBalancer() *IPHashBalancer {
	return &IPHashBalancer{
		stats: make(map[string]int64),
	}
}

// Select implements IP hash selection
func (i *IPHashBalancer) Select(services []*discovery.Service, request *Request) (*discovery.Service, error) {
	healthyServices := filterHealthyServices(services)
	if len(healthyServices) == 0 {
		return nil, fmt.Errorf("no healthy services available")
	}

	// Hash the client IP
	hasher := sha256.New()
	hasher.Write([]byte(request.ClientIP))
	hash := hasher.Sum(nil)
	
	// Convert hash to index
	hashValue := uint64(0)
	for _, b := range hash[:8] { // Use first 8 bytes
		hashValue = hashValue*256 + uint64(b)
	}
	
	index := hashValue % uint64(len(healthyServices))
	selected := healthyServices[index]

	i.mutex.Lock()
	i.stats[selected.ID]++
	i.mutex.Unlock()

	return selected, nil
}

// UpdateHealth is a no-op for IP hash
func (i *IPHashBalancer) UpdateHealth(serviceID string, health discovery.HealthStatus) {
	// IP hash doesn't need to track health separately
}

// GetStats returns selection statistics
func (i *IPHashBalancer) GetStats() map[string]interface{} {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	
	stats := make(map[string]interface{})
	stats["strategy"] = "ip_hash"
	stats["selections"] = make(map[string]int64)
	
	for serviceID, count := range i.stats {
		stats["selections"].(map[string]int64)[serviceID] = count
	}
	
	return stats
}

// Reset resets the balancer state
func (i *IPHashBalancer) Reset() {
	i.mutex.Lock()
	i.stats = make(map[string]int64)
	i.mutex.Unlock()
}

// Utility functions

// filterHealthyServices returns only healthy services
func filterHealthyServices(services []*discovery.Service) []*discovery.Service {
	var healthy []*discovery.Service
	for _, service := range services {
		if service.IsReady() { // IsReady includes passing and warning states
			healthy = append(healthy, service)
		}
	}
	return healthy
}

// CreateLoadBalancer creates a load balancer based on strategy
func CreateLoadBalancer(strategy Strategy, config map[string]interface{}) LoadBalancer {
	switch strategy {
	case StrategyRoundRobin:
		return NewRoundRobinBalancer()
	case StrategyWeightedRoundRobin:
		weights := make(map[string]int)
		if w, ok := config["weights"].(map[string]int); ok {
			weights = w
		}
		return NewWeightedRoundRobinBalancer(weights)
	case StrategyRandom:
		return NewRandomBalancer()
	case StrategyConsistentHash:
		replicas := 100
		if r, ok := config["replicas"].(int); ok {
			replicas = r
		}
		return NewConsistentHashBalancer(replicas)
	case StrategyIPHash:
		return NewIPHashBalancer()
	default:
		return NewRoundRobinBalancer() // Default to round-robin
	}
}