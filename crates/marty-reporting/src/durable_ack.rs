//! Exact queue acknowledgements for the Organization offline-ingestion API.
//! Uses the existing native event DTO; the receiver owns business validation.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use reqwest::{Client, Response, Url};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{ApiAcknowledgement, EventPayload, ReportingConfig, VerificationEvent};

pub(crate) const CONTRACT: &str = "offline-verification-ingest.v1";
const RECEIPT_KIND: &str = "offline-verification-receipt.v1";
const MAX_BODY_BYTES: usize = 131_072;
const INVALID_ACK: &str = "offline reporting did not return an exact durable batch acknowledgement";
const INVALID_AUTHORITY: &str =
    "offline reporting authority was not authenticated for the configured organization";

pub(crate) struct Destination {
    endpoint: Url,
    organization_id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authority {
    kind: String,
    organization_id: Uuid,
    producer_id: Uuid,
    max_batch: usize,
    receipt_storage: String,
    scope: String,
    evidence: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgement {
    kind: String,
    accepted: usize,
    duplicates: usize,
    receipts: Vec<Receipt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    kind: String,
    audit_event_id: Uuid,
    organization_id: Uuid,
    producer_id: Uuid,
    event_id: Uuid,
    verification_id: Uuid,
    payload_sha256: String,
    received_at: DateTime<Utc>,
    event: Value,
}

struct ExpectedEvent {
    verification_id: Uuid,
    timestamp: DateTime<Utc>,
    payload_sha256: String,
    event: Value,
}

pub(crate) struct ExpectedBatch(BTreeMap<Uuid, ExpectedEvent>);

impl Destination {
    pub fn for_config(config: &ReportingConfig) -> Result<Option<Self>, &'static str> {
        let explicit = config.api_acknowledgement == ApiAcknowledgement::OfflineVerificationV1;
        let parsed = config
            .api_endpoint
            .as_deref()
            .and_then(|raw| Url::parse(raw).ok());
        let known_route = parsed.as_ref().is_some_and(|url| {
            url.path()
                .trim_end_matches('/')
                .ends_with("/offline-verification-events")
        });
        if !explicit && !known_route {
            return Ok(None);
        }
        let url = parsed.ok_or("offline reporting requires the organization API endpoint")?;
        let parts: Vec<_> = url.path().split('/').collect();
        let organization_id = if parts.len() == 5
            && parts[1] == "v1"
            && parts[2] == "organizations"
            && parts[4] == "offline-verification-events"
        {
            canonical_uuid(parts[3])
                .ok_or("offline reporting requires a canonical organization UUID")?
        } else {
            return Err("offline reporting requires the exact organization ingestion path");
        };
        let host = url.host_str().unwrap_or_default();
        let deployed_https = url.scheme() == "https"
            && host.contains('.')
            && host.parse::<std::net::IpAddr>().is_err()
            && !["localhost", "local", "internal"]
                .iter()
                .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")));
        // Only unit tests permit their owned loopback HTTP fixture servers.
        let test_loopback = cfg!(test)
            && url.scheme() == "http"
            && matches!(host, "127.0.0.1" | "[::1]" | "localhost");
        if (!deployed_https && !test_loopback)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || Some(url.as_str()) != config.api_endpoint.as_deref()
            || config
                .api_key
                .as_deref()
                .is_none_or(|key| key.is_empty() || key.trim() != key)
        {
            return Err("offline reporting requires canonical deployed HTTPS and an API key");
        }
        Ok(Some(Self {
            endpoint: url,
            organization_id,
        }))
    }

    pub async fn authorize(
        &self,
        client: &Client,
        api_key: &str,
    ) -> Result<Authority, &'static str> {
        let response = client
            .get(self.endpoint.clone())
            .bearer_auth(api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|_| INVALID_AUTHORITY)?;
        let authority: Authority = bounded_json(response, &self.endpoint)
            .await
            .map_err(|_| INVALID_AUTHORITY)?;
        if authority.kind != CONTRACT
            || authority.organization_id != self.organization_id
            || !uuid_v4(authority.producer_id)
            || authority.max_batch != 100
            || authority.receipt_storage != "organization_service.audit_events"
            || authority.scope != "authenticated_api_key"
            || authority.evidence != "client_reported_offline_verification"
        {
            return Err(INVALID_AUTHORITY);
        }
        Ok(authority)
    }

    pub async fn require_acknowledgement(
        &self,
        response: Response,
        authority: &Authority,
        expected: &ExpectedBatch,
    ) -> Result<(), &'static str> {
        let acknowledgement: Acknowledgement = bounded_json(response, &self.endpoint).await?;
        validate_acknowledgement(acknowledgement, authority, expected, Utc::now())
    }
}

impl ExpectedBatch {
    pub fn from_request(body: &Value) -> Result<Self, &'static str> {
        let events = body
            .get("events")
            .and_then(Value::as_array)
            .ok_or(INVALID_ACK)?;
        if events.is_empty() || events.len() > 100 {
            return Err(INVALID_ACK);
        }
        let mut expected = BTreeMap::new();
        let mut verification_ids = BTreeSet::new();
        for value in events {
            let event: VerificationEvent =
                serde_json::from_value(value.clone()).map_err(|_| INVALID_ACK)?;
            let EventPayload::Verification(payload) = &event.payload else {
                return Err(INVALID_ACK);
            };
            let event_id = canonical_uuid(&event.event_id).ok_or(INVALID_ACK)?;
            let verification_id = canonical_uuid(&payload.verification_id).ok_or(INVALID_ACK)?;
            // Reuse native serialization and reject silently discarded fields.
            // This is correlation, not a copy of the receiver's policy allowlist.
            if serde_json::to_value(&event).map_err(|_| INVALID_ACK)? != *value
                || expected.contains_key(&event_id)
                || !verification_ids.insert(verification_id)
            {
                return Err(INVALID_ACK);
            }
            let encoded = serde_json::to_vec(&event).map_err(|_| INVALID_ACK)?;
            let payload_sha256 = ring::digest::digest(&ring::digest::SHA256, &encoded)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            expected.insert(
                event_id,
                ExpectedEvent {
                    verification_id,
                    timestamp: event.timestamp,
                    payload_sha256,
                    event: value.clone(),
                },
            );
        }
        Ok(Self(expected))
    }
}

fn validate_acknowledgement(
    acknowledgement: Acknowledgement,
    authority: &Authority,
    expected: &ExpectedBatch,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if acknowledgement.kind != CONTRACT
        || acknowledgement
            .accepted
            .checked_add(acknowledgement.duplicates)
            != Some(expected.0.len())
        || acknowledgement.receipts.len() != expected.0.len()
    {
        return Err(INVALID_ACK);
    }
    let mut event_ids = BTreeSet::new();
    let mut receipt_ids = BTreeSet::new();
    for receipt in acknowledgement.receipts {
        let event = expected.0.get(&receipt.event_id).ok_or(INVALID_ACK)?;
        if receipt.kind != RECEIPT_KIND
            || !uuid_v4(receipt.audit_event_id)
            || !event_ids.insert(receipt.event_id)
            || !receipt_ids.insert(receipt.audit_event_id)
            || receipt.organization_id != authority.organization_id
            || receipt.producer_id != authority.producer_id
            || receipt.verification_id != event.verification_id
            || receipt.event != event.event
            || receipt.payload_sha256 != event.payload_sha256
            || receipt.received_at > now + Duration::minutes(5)
            || receipt.received_at < event.timestamp - Duration::minutes(5)
        {
            return Err(INVALID_ACK);
        }
    }
    Ok(())
}

async fn bounded_json<T: DeserializeOwned>(
    mut response: Response,
    endpoint: &Url,
) -> Result<T, &'static str> {
    if response.status() != reqwest::StatusCode::OK
        || response.url() != endpoint
        || response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
        || response
            .content_length()
            .is_some_and(|size| size > MAX_BODY_BYTES as u64)
    {
        return Err(INVALID_ACK);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| INVALID_ACK)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err(INVALID_ACK);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| INVALID_ACK)
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(value).ok()?;
    (uuid_v4(id) && id.to_string() == value).then_some(id)
}

fn uuid_v4(value: Uuid) -> bool {
    value.get_version_num() == 4 && value.get_variant() == uuid::Variant::RFC4122
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{reporter::tests::reporter_with_config, Reporter};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
    };

    const ORG: &str = "28d552e4-4a94-4fd6-9b60-55e5e9ccb1a3";
    const PRODUCER: &str = "f2040e07-ae92-4e83-9fb8-083fa427c5fc";
    const KEY: &str = "synthetic-scoped-test-key-never-persist";

    fn config(endpoint: String) -> ReportingConfig {
        ReportingConfig {
            api_endpoint: Some(endpoint),
            api_key: Some(KEY.into()),
            api_acknowledgement: ApiAcknowledgement::OfflineVerificationV1,
            max_retries: 0,
            ..ReportingConfig::default()
        }
    }

    fn event() -> VerificationEvent {
        VerificationEvent::verification(Uuid::new_v4().to_string(), "dtc".into(), "valid".into())
            .with_verification_context(
                Some("UTO".into()),
                Some("x509".into()),
                true,
                Some(24),
                None,
            )
    }

    fn capability() -> Value {
        json!({"kind":CONTRACT,"organization_id":ORG,"producer_id":PRODUCER,"max_batch":100,
            "receipt_storage":"organization_service.audit_events","scope":"authenticated_api_key",
            "evidence":"client_reported_offline_verification"})
    }

    // Synthetic transport fixture, not deployed persistence evidence. The real
    // receiver's PostgreSQL atomicity/readback is tested in marty-organization.
    fn acknowledgement(body: &Value, duplicate: bool) -> Value {
        let expected = ExpectedBatch::from_request(body).unwrap();
        let receipts:Vec<_> = expected.0.iter().map(|(id,event)| json!({
            "kind":RECEIPT_KIND,"audit_event_id":Uuid::new_v4(),"organization_id":ORG,"producer_id":PRODUCER,
            "event_id":id,"verification_id":event.verification_id,"payload_sha256":event.payload_sha256,
            "received_at":Utc::now(),"event":event.event,
        })).collect();
        json!({"kind":CONTRACT,"accepted":if duplicate {0} else {receipts.len()},
            "duplicates":if duplicate {receipts.len()} else {0},"receipts":receipts})
    }

    #[test]
    fn native_digest_matches_the_frozen_organization_receiver_contract() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/offline-verification-ingest.json"
        ))
        .unwrap();
        let expected = ExpectedBatch::from_request(&fixture["native_request"]).unwrap();
        assert_eq!(
            expected.0.values().next().unwrap().payload_sha256,
            "9ba68c00fdda57e68e46098d4732c9c112bbaa20b4cbbd3ad1a0b3fc01d3a4a8"
        );
    }

    #[test]
    fn durable_policy_is_explicit_and_the_known_endpoint_cannot_downgrade() {
        let endpoint =
            format!("https://audit.example.net/v1/organizations/{ORG}/offline-verification-events");
        assert!(Destination::for_config(&config(endpoint.clone()))
            .unwrap()
            .is_some());
        let mut known = config(endpoint.clone());
        known.api_acknowledgement = ApiAcknowledgement::HttpStatus;
        assert!(Destination::for_config(&known).unwrap().is_some());
        for invalid in [
            endpoint.replace("https:", "http:"),
            format!("{endpoint}?token=secret"),
            format!("{endpoint}/"),
            endpoint.replace(ORG, "not-an-organization"),
            endpoint.replace("audit.example.net", "name:secret@audit.example.net"),
        ] {
            assert!(Destination::for_config(&config(invalid)).is_err());
        }
        let legacy: ReportingConfig = serde_json::from_value(json!({"enabled":true,"api_endpoint":"https://audit.example.net/generic",
            "api_key":null,"batch_endpoint":null,"local_only":false,"batch_interval_minutes":15,
            "max_queue_size":100,"max_retries":0,"redacted_fields":[],"include_hardware_info":false})).unwrap();
        assert_eq!(legacy.api_acknowledgement, ApiAcknowledgement::HttpStatus);
        assert!(Destination::for_config(&legacy).unwrap().is_none());
        assert_eq!(
            serde_json::to_value(&legacy).unwrap()["api_acknowledgement"],
            "http-status"
        );
        let mut batch = config(endpoint);
        batch.batch_endpoint = batch.api_endpoint.take();
        assert!(Destination::for_config(&batch).is_err());
    }

    #[test]
    fn durable_ack_requires_every_exact_event_and_an_authenticated_receipt() {
        let body = json!({"events":[event(),event()]});
        let expected = ExpectedBatch::from_request(&body).unwrap();
        let authority: Authority = serde_json::from_value(capability()).unwrap();
        for duplicate in [false, true] {
            let ack = serde_json::from_value(acknowledgement(&body, duplicate)).unwrap();
            assert!(validate_acknowledgement(ack, &authority, &expected, Utc::now()).is_ok());
        }
        for fault in [
            "count",
            "missing",
            "extra",
            "duplicate",
            "hash",
            "event",
            "verification",
            "org",
            "producer",
            "payload",
        ] {
            let mut ack = acknowledgement(&body, false);
            match fault {
                "count" => ack["accepted"] = json!(1),
                "missing" => {
                    ack["receipts"].as_array_mut().unwrap().pop();
                }
                "extra" => {
                    let extra = ack["receipts"][0].clone();
                    ack["receipts"].as_array_mut().unwrap().push(extra);
                }
                "duplicate" => ack["receipts"][1] = ack["receipts"][0].clone(),
                "hash" => ack["receipts"][0]["payload_sha256"] = json!("0".repeat(64)),
                "event" => ack["receipts"][0]["event_id"] = json!(Uuid::new_v4()),
                "verification" => ack["receipts"][0]["verification_id"] = json!(Uuid::new_v4()),
                "org" => ack["receipts"][0]["organization_id"] = json!(Uuid::new_v4()),
                "producer" => ack["receipts"][0]["producer_id"] = json!(Uuid::new_v4()),
                _ => ack["receipts"][0]["event"]["payload"]["result"] = json!("invalid"),
            }
            assert!(
                validate_acknowledgement(
                    serde_json::from_value(ack).unwrap(),
                    &authority,
                    &expected,
                    Utc::now()
                )
                .is_err(),
                "{fault}"
            );
        }
    }

    async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, Value) {
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0u8; 2048];
            let read = socket.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buffer[..read]);
            assert!(bytes.len() < MAX_BODY_BYTES);
            let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..end]).to_string();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                let body = if length == 0 {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap()
                };
                return (headers, body);
            }
        }
    }

    async fn server(
        fault: &'static str,
        pause: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "http://{}/v1/organizations/{ORG}/offline-verification-events",
            listener.local_addr().unwrap()
        );
        let task = tokio::spawn(async move {
            let mut pause = pause;
            for phase in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (headers, body) = read_request(&mut socket).await;
                assert!(headers
                    .to_ascii_lowercase()
                    .contains(&format!("authorization: bearer {KEY}")));
                let mut status = "200 OK";
                let mut extra = "";
                let mut payload = if phase == 0 {
                    assert!(headers.starts_with("GET "));
                    if fault == "authority" {
                        json!({"ok":true})
                    } else {
                        capability()
                    }
                } else {
                    assert!(headers.starts_with("POST "));
                    if let Some((started, resume)) = pause.take() {
                        started.send(()).unwrap();
                        resume.await.unwrap();
                    }
                    if fault == "disconnect" {
                        break;
                    }
                    let mut value = acknowledgement(&body, fault == "duplicate");
                    match fault {
                        "empty204" => {
                            status = "204 No Content";
                            value = Value::Null;
                        }
                        "empty200" => value = Value::Null,
                        "hash" => value["receipts"][0]["payload_sha256"] = json!("0".repeat(64)),
                        "producer" => value["receipts"][0]["producer_id"] = json!(Uuid::new_v4()),
                        "missing" => {
                            value["receipts"].as_array_mut().unwrap().pop();
                        }
                        "redirect" => {
                            status = "302 Found";
                            extra = "Location: /not-an-audit-receiver\r\n";
                        }
                        _ => {}
                    }
                    value
                }
                .to_string();
                if phase == 1 && fault == "oversized" {
                    payload = " ".repeat(MAX_BODY_BYTES + 1);
                }
                let wire=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{payload}",payload.len());
                let _ = socket.write_all(wire.as_bytes()).await;
                if fault == "authority" {
                    break;
                }
            }
        });
        (endpoint, task)
    }

    #[tokio::test]
    async fn durable_transport_keeps_the_real_queue_on_missing_invalid_or_oversized_acknowledgement(
    ) {
        for fault in [
            "empty204",
            "empty200",
            "hash",
            "producer",
            "missing",
            "oversized",
            "redirect",
            "authority",
            "disconnect",
        ] {
            let (endpoint, server) = server(fault, None).await;
            let (_directory, storage, reporter) = reporter_with_config(config(endpoint));
            reporter.queue_event(event()).await.unwrap();
            reporter.queue_event(event()).await.unwrap();
            let before = storage
                .get_pending_events(100)
                .await
                .unwrap()
                .iter()
                .map(|e| e.id.clone())
                .collect::<Vec<_>>();
            let error = reporter.flush().await.unwrap_err().to_string();
            assert!(!error.contains(KEY), "{fault}");
            let after = storage.get_pending_events(100).await.unwrap();
            assert_eq!(
                after.iter().map(|e| e.id.clone()).collect::<Vec<_>>(),
                before,
                "{fault}"
            );
            assert!(after.iter().all(|e| e.retry_count == 1), "{fault}");
            let status = storage.get_queue_status().await.unwrap();
            assert_eq!(status.pending_events, 2);
            assert!(status.last_successful_sync.is_none());
            assert!(!status.last_error.unwrap().contains(KEY));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn durable_duplicate_receipt_deletes_only_the_submitted_batch_after_a_lost_response() {
        let (endpoint, first_server) = server("disconnect", None).await;
        let (_directory, storage, reporter) = reporter_with_config(config(endpoint));
        let reporter = Arc::new(reporter);
        reporter.queue_event(event()).await.unwrap();
        reporter.queue_event(event()).await.unwrap();
        assert!(reporter.flush().await.is_err());
        first_server.await.unwrap();
        let (started, at_request) = oneshot::channel();
        let (resume, continue_request) = oneshot::channel();
        let (endpoint, second_server) =
            server("duplicate", Some((started, continue_request))).await;
        reporter.set_config(config(endpoint)).await;
        let flushing: Arc<Reporter> = Arc::clone(&reporter);
        let task = tokio::spawn(async move { flushing.flush().await });
        at_request.await.unwrap();
        let additional = event();
        let additional_id = additional.event_id.clone();
        reporter.queue_event(additional).await.unwrap();
        resume.send(()).unwrap();
        assert_eq!(task.await.unwrap().unwrap(), 2);
        second_server.await.unwrap();
        let pending = storage.get_pending_events(100).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].payload["event_id"], additional_id);
        assert!(storage
            .get_queue_status()
            .await
            .unwrap()
            .last_successful_sync
            .is_some());
    }
}
