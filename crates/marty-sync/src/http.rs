//! Authenticated JSON transport shared by policy and profile sync.

use crate::SyncError;
use reqwest::{Client, Method, RequestBuilder, Url};
use serde::de::DeserializeOwned;

pub(crate) struct SyncHttpClient {
    client: Client,
    endpoint: String,
    access_token: String,
}

impl SyncHttpClient {
    pub(crate) fn new(endpoint: String, access_token: String) -> Self {
        Self {
            client: Client::new(),
            endpoint,
            access_token,
        }
    }

    fn request(&self, method: Method, path: &[&str]) -> Result<RequestBuilder, SyncError> {
        let mut url =
            Url::parse(&self.endpoint).map_err(|e| SyncError::NetworkError(e.to_string()))?;
        // Endpoint configuration identifies a base path, not request parameters.
        if url.query().is_some() || url.fragment().is_some() {
            return Err(SyncError::NetworkError(
                "Sync endpoint must not contain a query or fragment".into(),
            ));
        }
        if path.iter().any(|segment| matches!(*segment, "." | "..")) {
            return Err(SyncError::NetworkError("Invalid sync path segment".into()));
        }
        url.path_segments_mut()
            .map_err(|()| {
                SyncError::NetworkError("Sync endpoint must support path segments".into())
            })?
            .pop_if_empty()
            .extend(path);
        Ok(self
            .client
            .request(method, url)
            .bearer_auth(&self.access_token))
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        path: &[&str],
        query: &[(&str, &str)],
        modified_since: Option<&str>,
        operation: &str,
    ) -> Result<T, SyncError> {
        let mut request = self.request(Method::GET, path)?;
        if !query.is_empty() {
            request = request.query(query);
        }
        if let Some(since) = modified_since {
            request = request.header("If-Modified-Since", since);
        }
        let response = request
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;
        if !response.status().is_success() {
            return Err(SyncError::HttpError(
                response.status().as_u16(),
                format!("Failed to fetch {operation}: {}", response.status()),
            ));
        }
        response
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))
    }

    pub(crate) async fn is_available(&self, path: &[&str]) -> bool {
        let Ok(request) = self.request(Method::HEAD, path) else {
            return false;
        };
        request
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PolicySyncProvider, ProfileSyncProvider};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn serve(status: &str, body: &str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/prefix/", listener.local_addr().unwrap());
        let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let task = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(5), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.unwrap();
                    bytes.push(byte[0]);
                    assert!(bytes.len() < 8192);
                }
                stream.write_all(response.as_bytes()).await.unwrap();
                String::from_utf8(bytes).unwrap()
            })
            .await
            .expect("local HTTP exchange timed out")
        });
        (endpoint, task)
    }

    fn assert_auth(request: &str) {
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token\r\n"));
    }

    #[test]
    fn base_paths_and_literal_percent_ids_are_preserved() {
        for base in ["http://localhost/prefix", "http://localhost/prefix/"] {
            let request = SyncHttpClient::new(base.into(), String::new())
                .request(Method::GET, &["devices", "%2F"])
                .unwrap()
                .build()
                .unwrap();
            assert_eq!(
                request.url().as_str(),
                "http://localhost/prefix/devices/%252F"
            );
        }
    }

    #[tokio::test]
    async fn policies_preserve_query_headers_and_empty_delta_contract() {
        let (endpoint, request) = serve("200 OK", "[]").await;
        let policies = PolicySyncProvider::new(endpoint, "fixture-token".into());
        assert!(policies
            .fetch_for_profile("a/b?x&y= z")
            .await
            .unwrap()
            .is_empty());
        let request = request.await.unwrap();
        assert_auth(&request);
        let target = request
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let url = Url::parse(&format!("http://localhost{target}")).unwrap();
        assert_eq!(
            url.path(),
            "/prefix/api/v1/identity/presentation-policies/sync"
        );
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![("deployment_profile_id".into(), "a/b?x&y= z".into())]
        );

        let (endpoint, request) = serve("200 OK", "[]").await;
        let policies = PolicySyncProvider::new(endpoint, "fixture-token".into());
        let since = "Sat, 05 Sep 2026 00:00:00 GMT";
        assert!(policies.fetch_delta(since).await.unwrap().is_empty());
        let request = request.await.unwrap();
        assert_auth(&request);
        assert!(request.contains(&format!("if-modified-since: {since}\r\n")));
    }

    #[tokio::test]
    async fn profile_routes_encode_identifiers_and_decode_their_own_types() {
        let id = "a/b?c#d";
        let (endpoint, request) = serve(
            "200 OK",
            r#"{"device_id":"device","deployment_profile":null,"lane":null}"#,
        )
        .await;
        let profiles = ProfileSyncProvider::new(endpoint, "fixture-token".into());
        assert_eq!(
            profiles.fetch_device_config(id).await.unwrap().device_id,
            "device"
        );
        let request = request.await.unwrap();
        assert_auth(&request);
        assert!(request.starts_with("GET /prefix/api/v1/devices/a%2Fb%3Fc%23d/config HTTP/1.1"));

        let body = serde_json::json!({
            "id":"profile", "name":"Profile", "site_id":null, "network_mode":"hybrid", "key_access_mode":"device",
            "ux_config":{"language":"en","theme":"dark","show_operator_mode":true,"accessibility_enabled":false,"signage_text":null},
            "update_policy":{"auto_update":false,"update_channel":"stable","rollout_percentage":50,"version_pinned":null,"rollout_ring":null},
            "offline_cache_ttl_hours":24,"operator_biometric_authentication_required":true,"audit_all_events":true
        }).to_string();
        let (endpoint, request) = serve("200 OK", &body).await;
        let profiles = ProfileSyncProvider::new(endpoint, "fixture-token".into());
        assert_eq!(
            profiles.fetch_deployment_profile(id).await.unwrap().id,
            "profile"
        );
        let request = request.await.unwrap();
        assert_auth(&request);
        assert!(request
            .starts_with("GET /prefix/api/v1/identity/deployment-profiles/a%2Fb%3Fc%23d HTTP/1.1"));

        let (endpoint, request) = serve("200 OK", "[]").await;
        let profiles = ProfileSyncProvider::new(endpoint, "fixture-token".into());
        assert!(profiles.fetch_lanes(id).await.unwrap().is_empty());
        let request = request.await.unwrap();
        assert_auth(&request);
        assert!(request.starts_with(
            "GET /prefix/api/v1/identity/deployment-profiles/a%2Fb%3Fc%23d/lanes HTTP/1.1"
        ));
    }

    #[tokio::test]
    async fn transport_preserves_status_parse_and_network_error_categories() {
        for (status, code) in [
            ("401 Unauthorized", 401),
            ("503 Service Unavailable", 503),
            ("304 Not Modified", 304),
        ] {
            let (endpoint, request) = serve(status, "").await;
            let error = PolicySyncProvider::new(endpoint, "fixture-token".into())
                .fetch_delta("Sat, 05 Sep 2026 00:00:00 GMT")
                .await
                .unwrap_err();
            assert!(
                matches!(error, SyncError::HttpError(actual, ref context) if actual == code && context.starts_with("Failed to fetch policy delta:"))
            );
            request.await.unwrap();
        }
        let (endpoint, request) = serve("200 OK", "not JSON").await;
        let error = PolicySyncProvider::new(endpoint, "fixture-token".into())
            .fetch_all()
            .await
            .unwrap_err();
        assert!(matches!(error, SyncError::ParseError(_)));
        request.await.unwrap();
        let policies = PolicySyncProvider::new("not a URL".into(), "fixture-token".into());
        assert!(matches!(
            policies.fetch_all().await,
            Err(SyncError::NetworkError(_))
        ));
        assert!(!policies.is_available().await);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let closed = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            PolicySyncProvider::new(endpoint, "fixture-token".into()).fetch_all(),
        )
        .await
        .expect("disconnected server request timed out");
        assert!(matches!(result, Err(SyncError::NetworkError(_))));
        closed.await.unwrap();
    }

    #[tokio::test]
    async fn availability_uses_authenticated_head_and_paths_reject_ambiguous_bases() {
        let (endpoint, request) = serve("200 OK", "").await;
        assert!(
            PolicySyncProvider::new(endpoint, "fixture-token".into())
                .is_available()
                .await
        );
        let request = request.await.unwrap();
        assert_auth(&request);
        assert!(request.starts_with("HEAD /prefix/api/v1/identity/presentation-policies HTTP/1.1"));
        for endpoint in [
            "http://localhost/base?x=1",
            "http://localhost/base#fragment",
        ] {
            assert!(SyncHttpClient::new(endpoint.into(), String::new())
                .request(Method::GET, &["api"])
                .is_err());
        }
        for id in [".", ".."] {
            assert!(
                SyncHttpClient::new("http://localhost".into(), String::new())
                    .request(Method::GET, &["devices", id])
                    .is_err()
            );
        }
    }
}
