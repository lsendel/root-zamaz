#!/bin/bash

# Incident Response and Rollback Script
# This script handles automated incident response and rollback procedures

set -e

# Configuration
APP_NAME="zamaz"
ENVIRONMENT=${1:-production}
NAMESPACE="${APP_NAME}-${ENVIRONMENT}"
INCIDENT_CHANNEL="#platform-incidents"
TEAMS_WEBHOOK=${TEAMS_WEBHOOK:-""}
SLACK_WEBHOOK=${SLACK_WEBHOOK:-""}

# Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Alert team
alert_team() {
    local severity=$1
    local message=$2

    # Slack notification
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 [$severity] $message\"}" \
            "$SLACK_WEBHOOK"
    fi

    # Microsoft Teams notification
    if [ -n "$TEAMS_WEBHOOK" ]; then
        curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"text\":\"🚨 [$severity] $message\"}" \
            "$TEAMS_WEBHOOK"
    fi
}

# Check if rollback is needed
check_health() {
    # Check error rate
    ERROR_RATE=$(curl -s "http://prometheus:9090/api/v1/query" \
        --data-urlencode 'query=sum(rate(http_requests_total{status=~"5.*"}[5m])) / sum(rate(http_requests_total[5m]))' \
        | jq '.data.result[0].value[1]')

    # Check latency
    P95_LATENCY=$(curl -s "http://prometheus:9090/api/v1/query" \
        --data-urlencode 'query=histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))' \
        | jq '.data.result[0].value[1]')

    if (( $(echo "$ERROR_RATE > 0.05" | bc -l) )) || (( $(echo "$P95_LATENCY > 0.5" | bc -l) )); then
        return 1
    fi
    return 0
}

# Perform rollback
rollback() {
    local revision=$1
    log "Initiating rollback to revision $revision"

    # Alert team about rollback
    alert_team "CRITICAL" "Initiating rollback to revision $revision due to health check failure"

    # Perform rollback using ArgoCD
    argocd app rollback ${APP_NAME}-${ENVIRONMENT} $revision

    # Wait for rollback to complete
    argocd app wait ${APP_NAME}-${ENVIRONMENT} --health

    # Verify health after rollback
    if check_health; then
        alert_team "INFO" "Rollback completed successfully"
        log "Rollback completed successfully"
    else
        alert_team "CRITICAL" "Rollback completed but health checks still failing"
        log "Rollback completed but health checks still failing"
        exit 1
    fi
}

# Collect diagnostics
collect_diagnostics() {
    local incident_id=$(date +%Y%m%d_%H%M%S)
    local diagnostic_dir="/tmp/incident_${incident_id}"

    mkdir -p "$diagnostic_dir"

    # Collect logs
    kubectl logs -n $NAMESPACE -l app=$APP_NAME --tail=1000 > "$diagnostic_dir/application_logs.txt"

    # Collect metrics
    curl -s "http://prometheus:9090/api/v1/query" \
        --data-urlencode 'query=rate(http_requests_total[1h])' \
        > "$diagnostic_dir/request_metrics.json"

    # Collect events
    kubectl get events -n $NAMESPACE > "$diagnostic_dir/kubernetes_events.txt"

    # Create incident report
    cat << EOF > "$diagnostic_dir/incident_report.md"
# Incident Report
- Incident ID: $incident_id
- Date: $(date)
- Environment: $ENVIRONMENT
- Error Rate: $ERROR_RATE
- P95 Latency: $P95_LATENCY

## Timeline
$(kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' | tail -n 10)

## Action Taken
- Automatic rollback initiated
- Diagnostic data collected
- Team notified

## Next Steps
1. Review application logs
2. Analyze metrics
3. Update runbook if needed
EOF

    # Archive and upload diagnostics
    tar -czf "$diagnostic_dir.tar.gz" -C "$diagnostic_dir" .

    # Upload to storage (implement according to your storage solution)
    # aws s3 cp "$diagnostic_dir.tar.gz" "s3://incident-logs/$incident_id.tar.gz"

    log "Diagnostic data collected and saved to $diagnostic_dir.tar.gz"
}

# Main execution
main() {
    log "Starting health check for $APP_NAME in $ENVIRONMENT"

    if ! check_health; then
        log "Health check failed - initiating incident response"

        # Get current revision
        current_revision=$(argocd app get ${APP_NAME}-${ENVIRONMENT} -o json | jq -r '.status.sync.revision')

        # Collect diagnostics
        collect_diagnostics

        # Perform rollback to last known good revision
        rollback $((current_revision-1))
    else
        log "Health check passed"
    fi
}

main "$@"
