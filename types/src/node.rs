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
            })),
            jwt_key,
            timeout,
            do_not_use,
        }
    }

    pub async fn set_synced(&self) {
        if self.do_not_use {
            // keep nodes that are marked not-for-use synced but never set them as online
            self.set_online_and_syncing().await;
            return;
        }

        let status = self.status.read().await;
        if status.status != SyncingStatus::Synced {
            tracing::info!(
                "Node {} is synced with a {}ms timeout",
                self.url,
                self.timeout.as_millis()
            );
            drop(status);
            let mut status = self.status.write().await;
            status.status = SyncingStatus::Synced;
        }
        // it's already set as synced
    }

    pub async fn set_offline(&self) {
        let status = self.status.read().await;
        if status.status != SyncingStatus::Offline {
            tracing::warn!("Node {} is offline", self.url);
            drop(status);
            let mut status = self.status.write().await;
            status.status = SyncingStatus::Offline;
        }
    }

    pub async fn set_online_and_syncing(&self) {
        let status = self.status.read().await;
        if status.status != SyncingStatus::OnlineAndSyncing {
            tracing::info!(
                "Node {} is online and syncing with a {}ms timeout",
                self.url,
                self.timeout.as_millis()
            );
            drop(status);
            let mut status = self.status.write().await;
            status.status = SyncingStatus::OnlineAndSyncing;
        }
    }

    pub async fn check_status(&self) -> Result<NodeHealth, reqwest::Error> {
        let start = std::time::Instant::now();
        let resp = self
            .authenticated_request()
            .json(&json!({"jsonrpc": "2.0", "method": "eth_syncing", "params": [], "id": 1}))
            .timeout(self.timeout)
            .send()
            .await;
        let resp_time = start.elapsed().as_micros();
        let resp: reqwest::Response = match resp {
            Ok(resp) => resp,
            Err(e) => {
                self.set_offline().await;
                return Err(e);
            }
        };

        // deserialize the json response.
        // result = false means node is online and not syncing
        // result = an object means node is syncing
        let json_body: serde_json::Value = resp.json().await?;
        let result = &json_body["result"];

        if result.is_boolean() {
            if !result.as_bool().unwrap() {
                // unwrap is safe due to check above
                self.set_synced().await;
            } else {
                self.set_online_and_syncing().await;
            }
        } else {
            // syncing nodes return a object reporting the sync status
            self.set_online_and_syncing().await;
        }

        // update the status
        let mut status = self.status.write().await;
        status.resp_time = resp_time;
        Ok(status.clone())
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
