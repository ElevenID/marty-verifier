//! Policy sync source for presentation policies

use crate::error::SyncError;
use marty_verification::policy::PresentationPolicy;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Policy sync provider for fetching presentation policies from backend
pub struct PolicySyncProvider {
    client: Client,
    endpoint: String,
    license_jwt: String,
}

impl PolicySyncProvider {
    /// Create a new policy sync provider
    ///
    /// # Arguments
    /// * `endpoint` - Backend API endpoint (e.g., "https://api.example.com")
    /// * `license_jwt` - License JWT for authentication
    pub fn new(endpoint: String, license_jwt: String) -> Self {
        Self {
            client: Client::new(),
            endpoint,
            license_jwt,
        }
    }

    /// Fetch all policies from the sync endpoint
    pub async fn fetch_all(&self) -> Result<Vec<PresentationPolicy>, SyncError> {
        self.fetch_with_filter(None).await
    }

    /// Fetch policies filtered by deployment profile ID
    ///
    /// # Arguments
    /// * `deployment_profile_id` - Optional deployment profile ID to filter by
    pub async fn fetch_for_profile(
        &self,
        deployment_profile_id: &str,
    ) -> Result<Vec<PresentationPolicy>, SyncError> {
        self.fetch_with_filter(Some(deployment_profile_id)).await
    }

    /// Internal method to fetch policies with optional filter
    async fn fetch_with_filter(
        &self,
        deployment_profile_id: Option<&str>,
    ) -> Result<Vec<PresentationPolicy>, SyncError> {
        let mut url = format!("{}/api/v1/identity/presentation-policies/sync", self.endpoint);

        if let Some(profile_id) = deployment_profile_id {
            url.push_str(&format!("?deployment_profile_id={}", profile_id));
        }

        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.license_jwt)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SyncError::HttpError(
                response.status().as_u16(),
                format!("Failed to fetch policies: {}", response.status()),
            ));
        }

        let policies: Vec<PresentationPolicy> = response
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        Ok(policies)
    }

    /// Fetch delta policies since a given timestamp
    ///
    /// # Arguments
    /// * `since` - RFC 2822 formatted timestamp
    pub async fn fetch_delta(&self, since: &str) -> Result<Vec<PresentationPolicy>, SyncError> {
        let url = format!("{}/api/v1/identity/presentation-policies/sync", self.endpoint);

        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.license_jwt)
            .header("If-Modified-Since", since)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SyncError::HttpError(
                response.status().as_u16(),
                format!("Failed to fetch policy delta: {}", response.status()),
            ));
        }

        let policies: Vec<PresentationPolicy> = response
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        Ok(policies)
    }

    /// Check if the sync endpoint is available
    pub async fn is_available(&self) -> bool {
        let url = format!("{}/api/v1/identity/presentation-policies", self.endpoint);

        self.client
            .head(&url)
            .bearer_auth(&self.license_jwt)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

/// Policy storage interface for local caching
#[allow(async_fn_in_trait)]
pub trait PolicyStorage {
    /// Store policies in local cache
    async fn store(&self, policies: &[PresentationPolicy]) -> Result<(), SyncError>;

    /// Get all cached policies
    async fn get_all(&self) -> Result<Vec<PresentationPolicy>, SyncError>;

    /// Get policy by ID
    async fn get_by_id(&self, id: &str) -> Result<Option<PresentationPolicy>, SyncError>;

    /// Get last sync timestamp
    async fn get_last_sync(&self) -> Result<Option<String>, SyncError>;

    /// Update last sync timestamp
    async fn update_last_sync(&self, timestamp: String) -> Result<(), SyncError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires live endpoint
    async fn test_fetch_policies() {
        let provider = PolicySyncProvider::new(
            "https://api.example.com".to_string(),
            "test_jwt".to_string(),
        );

        // This would fail without a real endpoint, but demonstrates usage
        let result = provider.fetch_all().await;
        assert!(result.is_err() || result.unwrap().is_empty());
    }
}
