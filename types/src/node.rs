use crate::*;
use reqwest;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

#[derive(Clone)]
pub struct NodeHealth {
    pub status: SyncingStatus,
    pub resp_time: u128,
    rpc_syncing: bool,
    forkchoice_generation: u64,
    forkchoice_ready: Option<bool>,
    observation_version: u64,
    probe_generation: u64,
}

#[derive(Clone)]
pub struct Node
// represents an EE
{
    pub client: reqwest::Client,
    pub url: String,
    pub status: Arc<RwLock<NodeHealth>>,
    pub jwt_key: JwtKey,
    pub timeout: Duration,
    pub do_not_use: bool,
}

impl Node {
    fn authenticated_request(&self) -> reqwest::RequestBuilder {
        self.client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .bearer_auth(make_jwt(&self.jwt_key).expect("HS256 signing failed"))
    }

    fn request_timeout(&self, method: &EngineMethod) -> Duration {
        // Amsterdam lowers newPayload's CL deadline to 6s. Leave time for
        // aggregation and the response, even if --timeout is larger.
        if *method == EngineMethod::engine_newPayloadV5 {
            self.timeout.min(Duration::from_millis(5500))
        } else {
            self.timeout
        }
    }

    pub fn new(url: String, jwt_key: JwtKey, timeout: Duration, do_not_use: bool) -> Node {
        let client = reqwest::Client::new();
        Node {
            client,
            url,
            status: Arc::new(RwLock::new(NodeHealth {
                status: SyncingStatus::NodeNotInitialized,
                resp_time: 0,
                rpc_syncing: true,
                forkchoice_generation: 0,
                forkchoice_ready: None,
                observation_version: 0,
                probe_generation: 0,
            })),
            jwt_key,
            timeout,
            do_not_use,
        }
    }

    fn update_readiness(&self, health: &mut NodeHealth) {
        // Forkchoice tells us whether this EL can validate the CL's selected
        // head. eth_syncing is only a fallback before that evidence exists.
        let ready = health.forkchoice_ready.unwrap_or(!health.rpc_syncing);
        let next = if ready && !self.do_not_use {
            SyncingStatus::Synced
        } else {
            SyncingStatus::OnlineAndSyncing
        };
        if health.status != next {
            tracing::info!("Node {} readiness changed to {:?}", self.url, next);
        }
        health.status = next;
    }

    pub async fn set_synced(&self) {
        let mut health = self.status.write().await;
        health.rpc_syncing = false;
        self.update_readiness(&mut health);
    }

    pub async fn set_offline(&self) {
        let mut health = self.status.write().await;
        health.status = SyncingStatus::Offline;
        // A disconnected/restarted EL must establish readiness again.
        if health.forkchoice_ready.is_some() {
            health.forkchoice_ready = Some(false);
        }
        health.observation_version += 1;
    }

    pub async fn set_online_and_syncing(&self) {
        let mut health = self.status.write().await;
        health.rpc_syncing = true;
        self.update_readiness(&mut health);
    }

    pub async fn begin_forkchoice(&self, generation: u64) {
        let mut health = self.status.write().await;
        health.forkchoice_generation = health.forkchoice_generation.max(generation);
    }

    pub async fn observe_forkchoice(&self, generation: u64, payload: &PayloadStatusV1, head: H256) {
        let ready = match payload.status {
            PayloadStatusV1Status::Syncing => false,
            PayloadStatusV1Status::Valid if payload.latest_valid_hash == Some(head) => true,
            // INVALID remains a validation vote, never a sync classification.
            _ => return,
        };
        let mut health = self.status.write().await;
        if generation != health.forkchoice_generation {
            return;
        }
        health.forkchoice_ready = Some(ready);
        health.observation_version += 1;
        self.update_readiness(&mut health);
    }

    pub async fn check_status(&self) -> Result<NodeHealth, reqwest::Error> {
        let (version, probe) = {
            let mut health = self.status.write().await;
            health.probe_generation += 1;
            (health.observation_version, health.probe_generation)
        };
        let start = std::time::Instant::now();
        let response = async {
            self.authenticated_request()
                .json(&json!({"jsonrpc": "2.0", "method": "eth_syncing", "params": [], "id": 1}))
                .timeout(self.timeout)
                .send()
                .await?
                .error_for_status()?
                .json::<serde_json::Value>()
                .await
        }
        .await;
        let mut health = self.status.write().await;
        // A probe started before a newer Engine response must not overwrite it,
        // including when that old probe times out or returns malformed JSON.
        if health.observation_version == version && health.probe_generation == probe {
            health.resp_time = start.elapsed().as_micros();
            match &response {
                Ok(body)
                    if body.get("error").is_none()
                        && (body["result"].is_boolean() || body["result"].is_object()) =>
                {
                    health.rpc_syncing = body["result"] != false;
                    self.update_readiness(&mut health);
                }
                _ => {
                    health.status = SyncingStatus::Offline;
                    if health.forkchoice_ready.is_some() {
                        health.forkchoice_ready = Some(false);
                    }
                    tracing::warn!("Node {} failed its health check", self.url);
                }
            }
        }
        response.map(|_| health.clone())
    }

    pub async fn do_request(&self, data: &RpcRequest) -> Result<String, reqwest::Error> {
        let resp = self
            .authenticated_request()
            .body(data.as_bytes())
            .timeout(self.request_timeout(&data.method))
            .send()
            .await;

        let resp = match resp {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Error while sending request to node {}: {}", self.url, e);
                return Err(e);
            }
        };

        let resp_body = resp.text().await?;
        Ok(resp_body)
    }

    pub async fn do_request_timeout(
        &self,
        data: &RpcRequest,
        timeout: Duration,
    ) -> Result<String, reqwest::Error> {
        let resp = self
            .authenticated_request()
            .body(data.as_bytes())
            .timeout(timeout)
            .send()
            .await;

        let resp = match resp {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Error while sending request to node {}: {}", self.url, e);
                return Err(e);
            }
        };

        let resp_body = resp.text().await?;
        Ok(resp_body)
    }

    pub async fn do_request_no_timeout(&self, data: &RpcRequest) -> Result<String, reqwest::Error> {
        let resp = self
            .authenticated_request()
            .body(data.as_bytes())
            .send()
            .await;

        let resp = match resp {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Error while sending request to node {}: {}", self.url, e);
                return Err(e);
            }
        };

        let resp_body = resp.text().await?;
        Ok(resp_body)
    }

    pub async fn do_request_no_timeout_str(&self, data: String) -> Result<String, reqwest::Error> {
        let resp = self.authenticated_request().body(data).send().await;

        let resp = match resp {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Error while sending request to node {}: {}", self.url, e);
                return Err(e);
            }
        };

        let resp_body = resp.text().await?;
        Ok(resp_body)
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[tokio::test]
    async fn readiness_requires_a_valid_response_for_the_latest_requested_head() {
        let node = Node::new(
            "http://127.0.0.1".into(),
            JwtKey::from_secret(&[1; 32]),
            Duration::from_secs(1),
            false,
        );
        let head = H256::repeat_byte(1);
        node.begin_forkchoice(1).await;
        node.observe_forkchoice(1, &PayloadStatusV1::new_syncing(), head)
            .await;
        let mut valid = PayloadStatusV1 {
            status: PayloadStatusV1Status::Valid,
            latest_valid_hash: Some(H256::repeat_byte(2)),
            validation_error: None,
        };
        node.begin_forkchoice(2).await;
        node.observe_forkchoice(2, &valid, head).await;
        assert_eq!(
            node.status.read().await.status,
            SyncingStatus::OnlineAndSyncing
        );
        valid.latest_valid_hash = Some(head);
        // Even before request 3 replies, request 2 can no longer promote the EL.
        node.begin_forkchoice(3).await;
        node.begin_forkchoice(2).await;
        node.observe_forkchoice(2, &valid, head).await;
        assert_eq!(
            node.status.read().await.status,
            SyncingStatus::OnlineAndSyncing
        );
        node.observe_forkchoice(3, &valid, head).await;
        assert_eq!(node.status.read().await.status, SyncingStatus::Synced);
        // Other indexing/sync work does not invalidate proof for this CL head.
        node.set_online_and_syncing().await;
        assert_eq!(node.status.read().await.status, SyncingStatus::Synced);
    }

    #[test]
    fn amsterdam_deadline_caps_only_longer_timeouts() {
        let mut node = Node::new(
            "http://127.0.0.1".into(),
            JwtKey::from_secret(&[1; 32]),
            Duration::from_secs(8),
            false,
        );
        assert_eq!(
            node.request_timeout(&EngineMethod::engine_newPayloadV5),
            Duration::from_millis(5500)
        );
        assert_eq!(
            node.request_timeout(&EngineMethod::engine_newPayloadV4),
            Duration::from_secs(8)
        );
        node.timeout = Duration::from_millis(500);
        assert_eq!(
            node.request_timeout(&EngineMethod::engine_newPayloadV5),
            node.timeout
        );
    }
}
