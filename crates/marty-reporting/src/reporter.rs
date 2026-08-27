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
    config: RwLock<ReportingConfig>,
    device_id: Option<String>,
    org_id: RwLock<Option<String>>,
}

impl Reporter {
    /// Create new reporter
    pub fn new(storage: Arc<SecureStorage>, config: ReportingConfig) -> Self {
        Self {
            storage,
            config: RwLock::new(config),
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

    /// Replace runtime reporting policy after the application configuration is saved.
    pub async fn set_config(&self, config: ReportingConfig) {
        *self.config.write().await = config;
    }

    /// Queue an event for reporting
    pub async fn queue_event(&self, mut event: VerificationEvent) -> Result<(), ReportingError> {
        let config = self.config.read().await.clone();
        if !config.enabled {
            return Err(ReportingError::Disabled);
        }

        // Add device and org context
        event.device_id = self.device_id.clone();
        event.org_id = self.org_id.read().await.clone();

        // Redact sensitive fields
        let event = self.redact_event(event);

        let queue_status = self.storage.get_queue_status().await?;
        if queue_status.pending_events >= config.max_queue_size {
            return Err(ReportingError::QueueFull {
                size: queue_status.pending_events,
                max: config.max_queue_size,
            });
        }

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

        Ok(())
    }

    /// Process queued events (batch upload)
    pub async fn flush(&self) -> Result<usize, ReportingError> {
        let config = self.config.read().await.clone();
        if !config.enabled || config.local_only {
            return Ok(0);
        }

        // Get pending events
        let events = self.storage.get_pending_events(100).await?;
        if events.is_empty() {
            return Ok(0);
        }

        #[cfg(not(feature = "api"))]
        return Err(ReportingError::Configuration(
            "remote reporting requires the marty-reporting api feature".to_string(),
        ));

        #[cfg(feature = "api")]
        {
            let destination = config
                .api_endpoint
                .as_ref()
                .map(|endpoint| (endpoint, false))
                .or_else(|| {
                    config
                        .batch_endpoint
                        .as_ref()
                        .map(|endpoint| (endpoint, true))
                })
                .ok_or_else(|| {
                    ReportingError::Configuration(
                        "remote reporting is enabled but no endpoint is configured".to_string(),
                    )
                })?;

            tracing::info!(count = events.len(), "Flushing queued events");
            let body = serde_json::json!({
                "events": events
                .iter()
                .map(|event| event.payload.clone())
                .collect::<Vec<_>>(),
            });
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|_| {
                    ReportingError::Network("reporting client initialization failed".to_string())
                })?;
            let mut last_error = None;

            let max_retries = config.max_retries.min(10);
            for attempt in 0..=max_retries {
                let mut request = if destination.1 {
                    // Presigned object-store batch destinations use PUT.
                    client.put(destination.0).json(&body)
                } else {
                    client.post(destination.0).json(&body)
                };
                if !destination.1 {
                    if let Some(api_key) = config.api_key.as_deref() {
                        request = request.bearer_auth(api_key);
                    }
                }

                let retryable = match request.send().await {
                    Ok(response) if response.status().is_success() => {
                        last_error = None;
                        break;
                    }
                    Ok(response) => {
                        let status = response.status();
                        last_error = Some(format!("reporting endpoint returned HTTP {}", status));
                        status.as_u16() == 429 || status.is_server_error()
                    }
                    Err(error) => {
                        last_error = Some(summarize_request_error(&error));
                        true
                    }
                };

                if retryable && attempt < max_retries {
                    let backoff_ms = 100_u64.saturating_mul(1_u64 << attempt.min(4));
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                } else {
                    break;
                }
            }

            if let Some(error) = last_error {
                let ids = events
                    .iter()
                    .map(|event| event.id.clone())
                    .collect::<Vec<_>>();
                self.storage
                    .record_queue_batch_failure(&ids, &error)
                    .await?;
                return Err(ReportingError::Network(error));
            }

            let ids = events
                .iter()
                .map(|event| event.id.clone())
                .collect::<Vec<_>>();
            Ok(self.storage.acknowledge_queue_batch(&ids).await?)
        }
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
        let config = self.config.read().await.clone();
        let queue_status = self.storage.get_queue_status().await?;

        Ok(ReportingStatus {
            enabled: config.enabled,
            local_only: config.local_only,
            pending_events: queue_status.pending_events,
            oldest_event: queue_status.oldest_event,
            last_successful_upload: queue_status.last_successful_sync,
            last_error: queue_status.last_error,
            api_configured: config.api_endpoint.is_some(),
            batch_configured: config.batch_endpoint.is_some(),
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
    pub last_error: Option<String>,
    pub api_configured: bool,
    pub batch_configured: bool,
}

#[cfg(feature = "api")]
fn summarize_request_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "reporting request timed out".to_string()
    } else if error.is_connect() {
        "reporting connection failed".to_string()
    } else if let Some(status) = error.status() {
        format!("reporting request failed with HTTP {status}")
    } else {
        "reporting request failed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReportingConfig;
    use std::sync::Once;
    #[cfg(feature = "api")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static INSTALL_MOCK_KEYRING: Once = Once::new();

    fn reporter_with_config(
        config: ReportingConfig,
    ) -> (tempfile::TempDir, Arc<SecureStorage>, Reporter) {
        INSTALL_MOCK_KEYRING.call_once(|| {
            keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        });
        let data_dir = tempfile::tempdir().unwrap();
        let storage =
            Arc::new(SecureStorage::new_with_process_local_keyring(data_dir.path()).unwrap());
        let reporter = Reporter::new(Arc::clone(&storage), config);
        (data_dir, storage, reporter)
    }

    #[cfg(feature = "api")]
    async fn one_response_server(status: &str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 2048];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().to_string())
                    })
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request).to_string();
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            request
        });
        (format!("http://{address}/events"), task)
    }

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
            last_error: None,
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
            last_error: None,
            api_configured: false,
            batch_configured: false,
        };

        assert_eq!(status.pending_events, 0);
        assert!(status.oldest_event.is_none());
    }

    #[tokio::test]
    async fn empty_queue_does_not_require_a_remote_endpoint() {
        let (_data_dir, _storage, reporter) = reporter_with_config(ReportingConfig::default());
        assert_eq!(reporter.flush().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn queue_limit_is_enforced_before_an_event_is_persisted() {
        let config = ReportingConfig {
            max_queue_size: 0,
            ..ReportingConfig::default()
        };
        let (_data_dir, storage, reporter) = reporter_with_config(config);
        let error = reporter
            .queue_event(VerificationEvent::verification(
                "verification-1".to_string(),
                "emrtd".to_string(),
                "valid".to_string(),
            ))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ReportingError::QueueFull { size: 0, max: 0 }
        ));
        assert_eq!(storage.get_queue_status().await.unwrap().pending_events, 0);
    }

    #[tokio::test]
    async fn runtime_configuration_changes_take_effect_without_restart() {
        let config = ReportingConfig {
            enabled: false,
            ..ReportingConfig::default()
        };
        let (_data_dir, storage, reporter) = reporter_with_config(config);
        let event = VerificationEvent::verification(
            "verification-runtime-config".to_string(),
            "emrtd".to_string(),
            "valid".to_string(),
        );

        assert!(matches!(
            reporter.queue_event(event.clone()).await,
            Err(ReportingError::Disabled)
        ));
        reporter.set_config(ReportingConfig::default()).await;
        reporter.queue_event(event).await.unwrap();

        assert_eq!(storage.get_queue_status().await.unwrap().pending_events, 1);
        assert!(reporter.get_status().await.unwrap().enabled);
    }

    #[tokio::test]
    #[cfg(feature = "api")]
    async fn failed_upload_keeps_the_durable_event() {
        let (endpoint, server) = one_response_server("503 Service Unavailable").await;
        let config = ReportingConfig {
            api_endpoint: Some(endpoint),
            max_retries: 0,
            ..ReportingConfig::default()
        };
        let (_data_dir, storage, reporter) = reporter_with_config(config);
        reporter
            .queue_event(VerificationEvent::verification(
                "verification-1".to_string(),
                "emrtd".to_string(),
                "valid".to_string(),
            ))
            .await
            .unwrap();

        let error = reporter.flush().await.unwrap_err();
        assert!(error.to_string().contains("HTTP 503"));
        let queue_status = storage.get_queue_status().await.unwrap();
        assert_eq!(queue_status.pending_events, 1);
        assert!(queue_status.last_sync_attempt.is_some());
        assert!(queue_status.last_successful_sync.is_none());
        assert_eq!(
            queue_status.last_error.as_deref(),
            Some("reporting endpoint returned HTTP 503 Service Unavailable")
        );
        let pending = storage.get_pending_events(10).await.unwrap();
        assert_eq!(pending[0].retry_count, 1);
        server.await.unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "api")]
    async fn request_failures_do_not_persist_destination_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let secret = "presigned-secret-must-not-persist";
        let config = ReportingConfig {
            batch_endpoint: Some(format!("http://{address}/events?token={secret}")),
            max_retries: 0,
            ..ReportingConfig::default()
        };
        let (_data_dir, storage, reporter) = reporter_with_config(config);
        reporter
            .queue_event(VerificationEvent::verification(
                "verification-no-secret".to_string(),
                "dtc".to_string(),
                "valid".to_string(),
            ))
            .await
            .unwrap();

        let error = reporter.flush().await.unwrap_err().to_string();
        assert!(!error.contains(secret));
        assert!(!error.contains("token="));
        let pending = storage.get_pending_events(10).await.unwrap();
        assert!(!pending[0].error.as_deref().unwrap().contains(secret));
        assert!(!storage
            .get_queue_status()
            .await
            .unwrap()
            .last_error
            .as_deref()
            .unwrap()
            .contains(secret));
    }

    #[tokio::test]
    #[cfg(feature = "api")]
    async fn acknowledged_upload_removes_the_exact_durable_batch() {
        let (endpoint, server) = one_response_server("204 No Content").await;
        let config = ReportingConfig {
            api_endpoint: Some(endpoint),
            api_key: Some("test-reporting-token".to_string()),
            ..ReportingConfig::default()
        };
        let (_data_dir, storage, reporter) = reporter_with_config(config);
        reporter
            .queue_event(VerificationEvent::verification(
                "verification-1".to_string(),
                "emrtd".to_string(),
                "valid".to_string(),
            ))
            .await
            .unwrap();

        assert_eq!(reporter.flush().await.unwrap(), 1);
        let queue_status = storage.get_queue_status().await.unwrap();
        assert_eq!(queue_status.pending_events, 0);
        assert!(queue_status.last_successful_sync.is_some());
        assert!(queue_status.last_error.is_none());
        let request = server.await.unwrap();
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer test-reporting-token"));
        assert!(request.contains("verification-1"));
    }

    #[tokio::test]
    #[cfg(feature = "api")]
    async fn presigned_batch_destination_uses_put() {
        let (endpoint, server) = one_response_server("200 OK").await;
        let config = ReportingConfig {
            batch_endpoint: Some(endpoint),
            api_key: Some("must-not-be-sent-to-presigned-destination".to_string()),
            max_retries: 0,
            ..ReportingConfig::default()
        };
        let (_data_dir, _storage, reporter) = reporter_with_config(config);
        reporter
            .queue_event(VerificationEvent::verification(
                "verification-2".to_string(),
                "dtc".to_string(),
                "valid".to_string(),
            ))
            .await
            .unwrap();

        assert_eq!(reporter.flush().await.unwrap(), 1);
        let request = server.await.unwrap();
        assert!(request.starts_with("PUT /events HTTP/1.1"));
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
    }

    #[tokio::test]
    #[cfg(not(feature = "api"))]
    async fn remote_flush_fails_closed_without_api_support_and_preserves_the_event() {
        let config = ReportingConfig {
            api_endpoint: Some("https://reporting.invalid/events".to_string()),
            ..ReportingConfig::default()
        };
        let (_data_dir, storage, reporter) = reporter_with_config(config);
        reporter
            .queue_event(VerificationEvent::verification(
                "verification-no-api".to_string(),
                "emrtd".to_string(),
                "valid".to_string(),
            ))
            .await
            .unwrap();

        let error = reporter.flush().await.unwrap_err();
        assert!(matches!(error, ReportingError::Configuration(_)));
        assert_eq!(storage.get_queue_status().await.unwrap().pending_events, 1);
    }
}
