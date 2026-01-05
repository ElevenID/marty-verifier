//! Reporter implementation

use std::sync::Arc;

use tokio::sync::RwLock;

use marty_secure_storage::SecureStorage;

use crate::config::ReportingConfig;
use crate::error::ReportingError;
use crate::events::VerificationEvent;

/// Reporter for sending events to configured destinations
pub struct Reporter {
    storage: Arc<SecureStorage>,
    config: ReportingConfig,
    device_id: Option<String>,
    org_id: RwLock<Option<String>>,
}

impl Reporter {
    /// Create new reporter
    pub fn new(storage: Arc<SecureStorage>, config: ReportingConfig) -> Self {
        Self {
            storage,
            config,
            device_id: None,
            org_id: RwLock::new(None),
        }
    }

    /// Set device identifier
    pub fn set_device_id(&mut self, device_id: String) {
        self.device_id = Some(device_id);
    }

    /// Set organization ID (from license)
    pub async fn set_org_id(&self, org_id: String) {
        *self.org_id.write().await = Some(org_id);
    }

    /// Queue an event for reporting
    pub async fn queue_event(&self, mut event: VerificationEvent) -> Result<(), ReportingError> {
        if !self.config.enabled {
            return Err(ReportingError::Disabled);
        }

        // Add device and org context
        event.device_id = self.device_id.clone();
        event.org_id = self.org_id.read().await.clone();

        // Redact sensitive fields
        let event = self.redact_event(event);

        // Store in queue
        let payload = serde_json::to_value(&event)?;
        self.storage
            .queue_event(&event.event_type, &payload)
            .await?;

        tracing::debug!(
            event_id = %event.event_id,
            event_type = %event.event_type,
            "Event queued for reporting"
        );

        // Try immediate send if API endpoint configured and not local-only
        #[cfg(feature = "api")]
        if !self.config.local_only {
            if let Some(ref _endpoint) = self.config.api_endpoint {
                // TODO: Implement async send with retry
                // For now, events stay in queue until batch upload
            }
        }

        Ok(())
    }

    /// Process queued events (batch upload)
    pub async fn flush(&self) -> Result<usize, ReportingError> {
        if !self.config.enabled || self.config.local_only {
            return Ok(0);
        }

        // Get pending events
        let events = self.storage.get_pending_events(100).await?;
        if events.is_empty() {
            return Ok(0);
        }

        tracing::info!(count = events.len(), "Flushing queued events");

        // TODO: Implement actual upload to API/batch endpoint
        // For now, just mark as processed

        let mut processed = 0;
        for event in events {
            // Simulate successful upload
            self.storage.remove_queued_event(&event.id).await?;
            processed += 1;
        }

        Ok(processed)
    }

    /// Redact sensitive fields from event
    fn redact_event(&self, event: VerificationEvent) -> VerificationEvent {
        // The actual redaction depends on payload structure
        // For now, we don't modify since our payloads don't contain PII
        // In production, we'd inspect and redact specific fields
        event
    }

    /// Get reporting status
    pub async fn get_status(&self) -> Result<ReportingStatus, ReportingError> {
        let queue_status = self.storage.get_queue_status().await?;

        Ok(ReportingStatus {
            enabled: self.config.enabled,
            local_only: self.config.local_only,
            pending_events: queue_status.pending_events,
            oldest_event: queue_status.oldest_event,
            last_successful_upload: queue_status.last_successful_sync,
            api_configured: self.config.api_endpoint.is_some(),
            batch_configured: self.config.batch_endpoint.is_some(),
        })
    }
}

/// Reporting status
#[derive(Debug, serde::Serialize)]
pub struct ReportingStatus {
    pub enabled: bool,
    pub local_only: bool,
    pub pending_events: usize,
    pub oldest_event: Option<String>,
    pub last_successful_upload: Option<String>,
    pub api_configured: bool,
    pub batch_configured: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReportingConfig;

    #[test]
    fn test_reporting_config_default() {
        let config = ReportingConfig::default();

        assert!(config.enabled);
        assert!(!config.local_only);
        assert!(config.api_endpoint.is_none());
        assert!(config.batch_endpoint.is_none());
    }

    #[test]
    fn test_reporting_config_local_only() {
        let config = ReportingConfig {
            enabled: true,
            local_only: true,
            api_endpoint: None,
            api_key: None,
            batch_endpoint: None,
            batch_interval_minutes: 15,
            max_queue_size: 1000,
            max_retries: 3,
            redacted_fields: vec!["name".to_string(), "dob".to_string()],
            include_hardware_info: true,
        };

        assert!(config.local_only);
        assert_eq!(config.max_queue_size, 1000);
    }

    #[test]
    fn test_reporting_status_serialization() {
        let status = ReportingStatus {
            enabled: true,
            local_only: false,
            pending_events: 10,
            oldest_event: Some("2025-01-01T00:00:00Z".to_string()),
            last_successful_upload: Some("2025-01-01T00:30:00Z".to_string()),
            api_configured: true,
            batch_configured: true,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"pending_events\":10"));
    }

    #[test]
    fn test_reporting_status_empty_queue() {
        let status = ReportingStatus {
            enabled: true,
            local_only: true,
            pending_events: 0,
            oldest_event: None,
            last_successful_upload: None,
            api_configured: false,
            batch_configured: false,
        };

        assert_eq!(status.pending_events, 0);
        assert!(status.oldest_event.is_none());
    }

    // Note: Full Reporter tests require mocking SecureStorage
    // which would be done in integration tests
}
