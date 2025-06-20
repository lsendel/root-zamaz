# Consul Configuration for MVP Zero Trust Auth
# Development Environment

datacenter = "dc1"
data_dir = "/consul/data"
log_level = "INFO"
node_name = "consul-dev"
server = true

# Client configuration
client_addr = "0.0.0.0"
bind_addr = "0.0.0.0"

# UI Configuration
ui_config {
  enabled = true
}

# Connect/Service Mesh Configuration
connect {
  enabled = true
}

ports {
  grpc = 8502
  http = 8500
  dns = 8600
}

# Performance and Limits
performance {
  raft_multiplier = 1
}

limits {
  http_max_conns_per_client = 200
  https_handshake_timeout = "5s"
  rpc_handshake_timeout = "5s"
  rpc_max_conns_per_client = 100
}

# Development mode settings
bootstrap_expect = 1
retry_join = []

# Service Discovery Configuration
services {
  name = "consul"
  port = 8500
  tags = ["consul", "service-discovery", "kv-store"]
  check {
    http = "http://localhost:8500/v1/status/leader"
    interval = "10s"
    timeout = "3s"
  }
}

# DNS Configuration
recursors = ["8.8.8.8", "1.1.1.1"]
dns_config {
  allow_stale = true
  max_stale = "5s"
  node_ttl = "30s"
  service_ttl = "30s"
  enable_truncate = true
}

# Security Configuration (Development)
acl = {
  enabled = false
  default_policy = "allow"
}

# Telemetry
telemetry {
  disable_hostname = false
  prometheus_retention_time = "60s"
  statsd_address = ""
}

# Autopilot (Enterprise Feature - disabled in dev)
autopilot {
  cleanup_dead_servers = true
  last_contact_threshold = "200ms"
  max_trailing_logs = 250
  server_stabilization_time = "10s"
}