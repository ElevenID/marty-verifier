//! Policy sync source for presentation policies

use crate::error::SyncError;
use crate::http::SyncHttpClient;
use marty_verification::policy::PresentationPolicy;

/// Policy sync provider for fetching presentation policies from backend
pub struct PolicySyncProvider {
    http: SyncHttpClient,
}

impl PolicySyncProvider {
    /// Create a new policy sync provider
    ///
    /// # Arguments
    /// * `endpoint` - Backend API endpoint (e.g., "https://api.example.com")
    /// * `access_token` - Optional bearer token for authentication
    pub fn new(endpoint: String, access_token: String) -> Self {
        Self {
            http: SyncHttpClient::new(endpoint, access_token),
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
        let query: Vec<_> = deployment_profile_id
            .map(|id| ("deployment_profile_id", id))
            .into_iter()
            .collect();
        self.http
            .get_json(
                &["api", "v1", "identity", "presentation-policies", "sync"],
                &query,
                None,
                "policies",
            )
            .await
    }

    /// Fetch delta policies since a given timestamp
    ///
    /// # Arguments
    /// * `since` - RFC 2822 formatted timestamp
    pub async fn fetch_delta(&self, since: &str) -> Result<Vec<PresentationPolicy>, SyncError> {
        self.http
            .get_json(
                &["api", "v1", "identity", "presentation-policies", "sync"],
                &[],
                Some(since),
                "policy delta",
            )
            .await
    }

    /// Check if the sync endpoint is available
    pub async fn is_available(&self) -> bool {
        self.http
            .is_available(&["api", "v1", "identity", "presentation-policies"])
            .await
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
