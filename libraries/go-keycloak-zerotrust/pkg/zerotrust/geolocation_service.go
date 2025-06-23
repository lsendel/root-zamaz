// Package zerotrust provides geolocation services for Zero Trust risk assessment
package zerotrust

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// GeolocationServiceImpl implements the GeolocationService interface
type GeolocationServiceImpl struct {
	config           *types.ZeroTrustConfig
	httpClient       *http.Client
	cache            map[string]*CachedLocationInfo
	userBaselines    UserBaselineStorage
	apiKey           string
	provider         string
	highRiskCountries map[string]bool
	vpnDetector      VPNDetector
}

// UserBaselineStorage interface for storing user location baselines
type UserBaselineStorage interface {
	GetUserLocationBaseline(ctx context.Context, userID string) ([]*types.LocationInfo, error)
	UpdateUserLocationBaseline(ctx context.Context, userID string, location *types.LocationInfo) error
}

// VPNDetector interface for detecting VPN/proxy usage
type VPNDetector interface {
	IsVPN(ctx context.Context, ipAddress string) (bool, error)
	IsTor(ctx context.Context, ipAddress string) (bool, error)
	IsProxy(ctx context.Context, ipAddress string) (bool, error)
}

// CachedLocationInfo represents cached location information
type CachedLocationInfo struct {
	Location  *types.LocationInfo `json:"location"`
	Timestamp time.Time           `json:"timestamp"`
	TTL       time.Duration       `json:"ttl"`
}

// ExternalLocationResponse represents response from external geolocation API
type ExternalLocationResponse struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	RegionCode  string  `json:"region_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Organization string `json:"organization"`
	AS          string  `json:"as"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
}

// SimpleVPNDetector provides basic VPN/proxy detection
type SimpleVPNDetector struct {
	knownVPNRanges []net.IPNet
	knownTorExits  map[string]bool
}

// NewGeolocationService creates a new geolocation service
func NewGeolocationService(config *types.ZeroTrustConfig, userBaselines UserBaselineStorage) *GeolocationServiceImpl {
	service := &GeolocationServiceImpl{
		config:        config,
		userBaselines: userBaselines,
		cache:         make(map[string]*CachedLocationInfo),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		highRiskCountries: map[string]bool{
			"CN": true, // China
			"RU": true, // Russia
			"IR": true, // Iran
			"KP": true, // North Korea
			"CU": true, // Cuba
			"SY": true, // Syria
		},
		vpnDetector: NewSimpleVPNDetector(),
	}

	// Configure geolocation provider
	if config.ZeroTrust != nil && config.ZeroTrust.GeolocationAPI != "" {
		service.provider = "external"
		service.apiKey = config.ZeroTrust.GeolocationAPI
	} else {
		service.provider = "internal"
	}

	log.Printf("Geolocation service initialized with provider: %s", service.provider)
	return service
}

// GetLocationInfo retrieves location information for an IP address
func (s *GeolocationServiceImpl) GetLocationInfo(ctx context.Context, ipAddress string) (*types.LocationInfo, error) {
	// Validate IP address
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	// Check for private/local IP addresses
	if s.isPrivateIP(ip) {
		return &types.LocationInfo{
			Country: "Local",
			Region:  "Private Network",
			City:    "Local",
			ISP:     "Private",
		}, nil
	}

	// Check cache first
	if cached := s.getCachedLocation(ipAddress); cached != nil {
		return cached, nil
	}

	var location *types.LocationInfo
	var err error

	// Get location based on configured provider
	switch s.provider {
	case "external":
		location, err = s.getLocationFromExternalAPI(ctx, ipAddress)
	default:
		location, err = s.getLocationFromInternalDB(ctx, ipAddress)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get location info: %w", err)
	}

	// Enhance with additional security information
	s.enhanceLocationInfo(ctx, ipAddress, location)

	// Cache the result
	s.cacheLocation(ipAddress, location)

	return location, nil
}

// CalculateLocationRisk calculates location-based risk for a user
func (s *GeolocationServiceImpl) CalculateLocationRisk(ctx context.Context, userID string, location *types.LocationInfo) (*LocationRisk, error) {
	risk := &LocationRisk{
		RiskScore:           0,
		IsHighRisk:          false,
		IsNewLocation:       false,
		DistanceFromTypical: 0,
		RiskReasons:         make([]string, 0),
		CountryRisk:         "low",
	}

	// Get user's typical locations
	baseline, err := s.userBaselines.GetUserLocationBaseline(ctx, userID)
	if err != nil {
		log.Printf("Failed to get user location baseline: %v", err)
		// Treat as new location if we can't get baseline
		risk.IsNewLocation = true
		risk.RiskScore += 30
		risk.RiskReasons = append(risk.RiskReasons, "no_location_history")
	} else {
		// Check if this is a new location
		isTypical, distance := s.isTypicalLocation(location, baseline)
		if !isTypical {
			risk.IsNewLocation = true
			risk.DistanceFromTypical = distance
			risk.RiskScore += 40
			risk.RiskReasons = append(risk.RiskReasons, "new_location")
			
			// Higher risk for very distant locations
			if distance > 1000 { // More than 1000km from typical
				risk.RiskScore += 20
				risk.RiskReasons = append(risk.RiskReasons, "distant_location")
			}
		}
	}

	// Check for high-risk countries
	if s.highRiskCountries[location.Country] {
		risk.RiskScore += 50
		risk.IsHighRisk = true
		risk.CountryRisk = "high"
		risk.RiskReasons = append(risk.RiskReasons, "high_risk_country")
	}

	// Check for VPN/Tor usage
	if s.vpnDetector != nil {
		if isVPN, err := s.vpnDetector.IsVPN(ctx, location.ISP); err == nil && isVPN {
			risk.VPNDetected = true
			risk.RiskScore += 30
			risk.RiskReasons = append(risk.RiskReasons, "vpn_detected")
		}

		if isTor, err := s.vpnDetector.IsTor(ctx, location.ISP); err == nil && isTor {
			risk.TorDetected = true
			risk.RiskScore += 60
			risk.IsHighRisk = true
			risk.RiskReasons = append(risk.RiskReasons, "tor_detected")
		}
	}

	// Determine overall risk level
	if risk.RiskScore >= 75 {
		risk.IsHighRisk = true
	}

	// Update user baseline with this location (if not too risky)
	if !risk.IsHighRisk && !risk.VPNDetected && !risk.TorDetected {
		if err := s.userBaselines.UpdateUserLocationBaseline(ctx, userID, location); err != nil {
			log.Printf("Failed to update user location baseline: %v", err)
		}
	}

	log.Printf("Location risk calculated for user %s: score=%d, new=%t, distance=%.1fkm",
		userID, risk.RiskScore, risk.IsNewLocation, risk.DistanceFromTypical)

	return risk, nil
}

// IsHighRiskLocation checks if a location is considered high risk
func (s *GeolocationServiceImpl) IsHighRiskLocation(ctx context.Context, location *types.LocationInfo) (bool, []string) {
	reasons := make([]string, 0)

	// Check high-risk countries
	if s.highRiskCountries[location.Country] {
		reasons = append(reasons, "high_risk_country")
	}

	// Check for suspicious ISP patterns
	if s.isSuspiciousISP(location.ISP) {
		reasons = append(reasons, "suspicious_isp")
	}

	// Check for known hosting providers (often used for bots/attacks)
	if s.isHostingProvider(location.ISP) {
		reasons = append(reasons, "hosting_provider")
	}

	return len(reasons) > 0, reasons
}

// Private helper methods

func (s *GeolocationServiceImpl) isPrivateIP(ip net.IP) bool {
	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, rangeStr := range privateRanges {
		_, network, _ := net.ParseCIDR(rangeStr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

func (s *GeolocationServiceImpl) getCachedLocation(ipAddress string) *types.LocationInfo {
	cached, exists := s.cache[ipAddress]
	if !exists {
		return nil
	}

	// Check if cache is still valid
	if time.Since(cached.Timestamp) > cached.TTL {
		delete(s.cache, ipAddress)
		return nil
	}

	return cached.Location
}

func (s *GeolocationServiceImpl) cacheLocation(ipAddress string, location *types.LocationInfo) {
	s.cache[ipAddress] = &CachedLocationInfo{
		Location:  location,
		Timestamp: time.Now(),
		TTL:       1 * time.Hour, // Cache for 1 hour
	}
}

func (s *GeolocationServiceImpl) getLocationFromExternalAPI(ctx context.Context, ipAddress string) (*types.LocationInfo, error) {
	// Example using a generic IP geolocation API
	url := fmt.Sprintf("http://ip-api.com/json/%s", ipAddress)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResponse ExternalLocationResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, err
	}

	return &types.LocationInfo{
		Country:   apiResponse.Country,
		Region:    apiResponse.Region,
		City:      apiResponse.City,
		Latitude:  apiResponse.Latitude,
		Longitude: apiResponse.Longitude,
		ISP:       apiResponse.ISP,
		Timezone:  apiResponse.Timezone,
	}, nil
}

func (s *GeolocationServiceImpl) getLocationFromInternalDB(ctx context.Context, ipAddress string) (*types.LocationInfo, error) {
	// Simplified internal geolocation using basic IP range mapping
	// In production, this would use a proper GeoIP database like MaxMind
	
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	// Very basic geolocation based on IP ranges (for demo purposes)
	location := &types.LocationInfo{
		Country: "Unknown",
		Region:  "Unknown",
		City:    "Unknown",
		ISP:     "Unknown",
	}

	// Example: Basic country detection based on IP ranges
	if s.isInRange(ip, "8.0.0.0/8") {
		location.Country = "US"
		location.Region = "California"
		location.City = "Mountain View"
		location.ISP = "Google"
	} else if s.isInRange(ip, "1.0.0.0/8") {
		location.Country = "CN"
		location.Region = "Beijing"
		location.City = "Beijing"
		location.ISP = "China Telecom"
	}

	return location, nil
}

func (s *GeolocationServiceImpl) enhanceLocationInfo(ctx context.Context, ipAddress string, location *types.LocationInfo) {
	// Add timezone if not present
	if location.Timezone == "" {
		location.Timezone = s.inferTimezone(location.Latitude, location.Longitude)
	}

	// Check for VPN/proxy indicators in the ISP name
	if s.isSuspiciousISP(location.ISP) {
		// Mark as potentially suspicious
		log.Printf("Suspicious ISP detected: %s for IP %s", location.ISP, ipAddress)
	}
}

func (s *GeolocationServiceImpl) isInRange(ip net.IP, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func (s *GeolocationServiceImpl) isTypicalLocation(current *types.LocationInfo, baseline []*types.LocationInfo) (bool, float64) {
	if len(baseline) == 0 {
		return false, 0
	}

	minDistance := math.MaxFloat64

	for _, typical := range baseline {
		distance := s.calculateDistance(
			current.Latitude, current.Longitude,
			typical.Latitude, typical.Longitude,
		)
		
		if distance < minDistance {
			minDistance = distance
		}

		// Consider typical if within 100km of any baseline location
		if distance <= 100 {
			return true, distance
		}
	}

	return false, minDistance
}

func (s *GeolocationServiceImpl) calculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	// Haversine formula for calculating distance between two points on Earth
	const earthRadiusKm = 6371

	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Sin(dLon/2)*math.Sin(dLon/2)*math.Cos(lat1Rad)*math.Cos(lat2Rad)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusKm * c
}

func (s *GeolocationServiceImpl) isSuspiciousISP(isp string) bool {
	suspiciousKeywords := []string{
		"vpn", "proxy", "tor", "hosting", "datacenter", "cloud", "server",
		"anonymous", "private", "tunnel", "shield", "hide", "mask",
	}

	ispLower := strings.ToLower(isp)
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(ispLower, keyword) {
			return true
		}
	}

	return false
}

func (s *GeolocationServiceImpl) isHostingProvider(isp string) bool {
	hostingKeywords := []string{
		"amazon", "aws", "google cloud", "microsoft azure", "digitalocean",
		"linode", "vultr", "ovh", "hetzner", "hosting", "datacenter", "server farm",
	}

	ispLower := strings.ToLower(isp)
	for _, keyword := range hostingKeywords {
		if strings.Contains(ispLower, keyword) {
			return true
		}
	}

	return false
}

func (s *GeolocationServiceImpl) inferTimezone(lat, lon float64) string {
	// Very simplified timezone inference based on longitude
	// In production, use a proper timezone database
	
	if lat == 0 && lon == 0 {
		return "UTC"
	}

	// Rough approximation: 15 degrees longitude = 1 hour
	hoursFromUTC := int(lon / 15)
	
	if hoursFromUTC >= 0 {
		return fmt.Sprintf("UTC+%d", hoursFromUTC)
	} else {
		return fmt.Sprintf("UTC%d", hoursFromUTC)
	}
}

// VPN Detector Implementation

// NewSimpleVPNDetector creates a new simple VPN detector
func NewSimpleVPNDetector() *SimpleVPNDetector {
	detector := &SimpleVPNDetector{
		knownVPNRanges: make([]net.IPNet, 0),
		knownTorExits:  make(map[string]bool),
	}

	// Add some known VPN/proxy ranges (simplified)
	vpnRanges := []string{
		"5.39.0.0/16",      // OVH (commonly used for VPNs)
		"37.59.0.0/16",     // OVH
		"163.172.0.0/16",   // Scaleway
		"217.70.184.0/24",  // Tor exit nodes
	}

	for _, rangeStr := range vpnRanges {
		if _, network, err := net.ParseCIDR(rangeStr); err == nil {
			detector.knownVPNRanges = append(detector.knownVPNRanges, *network)
		}
	}

	return detector
}

// IsVPN checks if an IP or ISP is likely a VPN
func (d *SimpleVPNDetector) IsVPN(ctx context.Context, ipOrISP string) (bool, error) {
	// Check if it's an IP address
	if ip := net.ParseIP(ipOrISP); ip != nil {
		for _, vpnRange := range d.knownVPNRanges {
			if vpnRange.Contains(ip) {
				return true, nil
			}
		}
		return false, nil
	}

	// Check ISP string for VPN indicators
	vpnKeywords := []string{"vpn", "proxy", "private", "tunnel", "shield", "hide"}
	ispLower := strings.ToLower(ipOrISP)
	
	for _, keyword := range vpnKeywords {
		if strings.Contains(ispLower, keyword) {
			return true, nil
		}
	}

	return false, nil
}

// IsTor checks if an IP is a known Tor exit node
func (d *SimpleVPNDetector) IsTor(ctx context.Context, ipOrISP string) (bool, error) {
	// Check if it's an IP address
	if ip := net.ParseIP(ipOrISP); ip != nil {
		return d.knownTorExits[ip.String()], nil
	}

	// Check ISP string for Tor indicators
	return strings.Contains(strings.ToLower(ipOrISP), "tor"), nil
}

// IsProxy checks if an IP or ISP is likely a proxy
func (d *SimpleVPNDetector) IsProxy(ctx context.Context, ipOrISP string) (bool, error) {
	// Similar logic to VPN detection
	return d.IsVPN(ctx, ipOrISP)
}