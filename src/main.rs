use axum::{
    self,
    extract::{self, DefaultBodyLimit},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Router,
};
use futures::future::join_all;

use node::NodeHealth;
use rand::RngCore;
use serde_json::json;
use std::{any::type_name, collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    sync::{Mutex, RwLock},
    time::Duration,
};
use tracing_subscriber::filter::EnvFilter;
mod verify_hash;
use regex::Regex;
use types::{node::Node, *};
use verify_hash::verify_payload_block_hash;

const VERSION: &str = "1.2.0";

// Select payload schemas by Engine API version. Fork activation and network
// configuration belong to the CL/EL; mainnet epoch arithmetic breaks testnets.
fn parse_new_payload(request: &RpcRequest) -> Result<NewPayloadRequest, String> {
    let params = request
        .params
        .as_array()
        .ok_or("Expected positional params")?;
    let count = match request.method {
        EngineMethod::engine_newPayloadV1 | EngineMethod::engine_newPayloadV2 => 1,
        EngineMethod::engine_newPayloadV3 => 3,
        EngineMethod::engine_newPayloadV4 | EngineMethod::engine_newPayloadV5 => 4,
        _ => return Err("Expected newPayload method".into()),
    };
    if params.len() != count {
        return Err(format!(
            "Expected {} params for {:?}",
            count, request.method
        ));
    }
    let execution_payload = match request.method {
        EngineMethod::engine_newPayloadV1 => {
            serde_json::from_value::<ExecutionPayloadV1>(params[0].clone())
                .map(ExecutionPayload::V1)
        }
        EngineMethod::engine_newPayloadV2 if params[0]["withdrawals"].is_null() => {
            serde_json::from_value::<ExecutionPayloadV1>(params[0].clone())
                .map(ExecutionPayload::V1)
        }
        EngineMethod::engine_newPayloadV2 => {
            serde_json::from_value::<ExecutionPayloadV2>(params[0].clone())
                .map(ExecutionPayload::V2)
        }
        EngineMethod::engine_newPayloadV5 => {
            serde_json::from_value::<ExecutionPayloadV4>(params[0].clone())
                .map(ExecutionPayload::V4)
        }
        _ => serde_json::from_value::<ExecutionPayloadV3>(params[0].clone())
            .map(ExecutionPayload::V3),
    }
    .map_err(|e| e.to_string())?;
    let mut parsed = NewPayloadRequest {
        execution_payload,
        expected_blob_versioned_hashes: None,
        parent_beacon_block_root: None,
        execution_requests: None,
    };
    if count >= 3 {
        parsed.expected_blob_versioned_hashes =
            Some(serde_json::from_value(params[1].clone()).map_err(|e| e.to_string())?);
        parsed.parent_beacon_block_root =
            Some(serde_json::from_value(params[2].clone()).map_err(|e| e.to_string())?);
    }
    if count == 4 {
        let requests: Vec<String> =
            serde_json::from_value(params[3].clone()).map_err(|e| e.to_string())?;
        let mut previous = None;
        for request in &requests {
            let bytes = hex::decode(
                request
                    .strip_prefix("0x")
                    .ok_or("Execution request must be DATA")?,
            )
            .map_err(|e| e.to_string())?;
            if bytes.len() <= 1 || previous.is_some_and(|prev| prev >= bytes[0]) {
                return Err(
                    "Execution requests must have data and unique types in ascending order".into(),
                );
            }
            previous = Some(bytes[0]);
        }
        parsed.execution_requests = Some(requests);
    }
    Ok(parsed)
}

fn make_response(id: &impl serde::Serialize, result: serde_json::Value) -> String {
    json!({"jsonrpc":"2.0","id":id,"result":result}).to_string()
}

fn rpc_error(id: &impl serde::Serialize, code: i32, message: &str) -> String {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}).to_string()
}

fn make_error(id: &impl serde::Serialize, error: &str) -> String {
    rpc_error(id, -32603, error)
}

fn make_syncing_str(request: &RpcRequest, payload: Option<&NewPayloadRequest>) -> String {
    if let Some(payload) = payload {
        if let Err(error) = verify_payload_block_hash(
            &payload.execution_payload,
            payload.parent_beacon_block_root,
            payload.execution_requests.as_deref(),
        ) {
            let status = if request.method == EngineMethod::engine_newPayloadV1 {
                "INVALID_BLOCK_HASH"
            } else {
                "INVALID"
            };
            return make_response(
                &request.id,
                json!({"status": status, "latestValidHash": null, "validationError": error.to_string()}),
            );
        }
        make_response(&request.id, json!(PayloadStatusV1::new_syncing()))
    } else {
        make_response(
            &request.id,
            json!(forkchoiceUpdatedResponse {
                payloadStatus: PayloadStatusV1::new_syncing(),
                payloadId: None,
            }),
        )
    }
}

struct PayloadBuild {
    created: std::time::Instant,
    nodes: Vec<PayloadIdNode>,
}

const PAYLOAD_CACHE_TTL: Duration = Duration::from_secs(120);
const MAX_PAYLOAD_BUILDS: usize = 1024;

struct NodeRouter {
    nodes: Arc<Mutex<Vec<Arc<Node>>>>,
    alive_nodes: Arc<RwLock<Vec<Arc<Node>>>>,
    dead_nodes: Arc<RwLock<Vec<Arc<Node>>>>,
    alive_but_syncing_nodes: Arc<RwLock<Vec<Arc<Node>>>>,

    // this node will be the selected primary node used to route all requests
    primary_node: Arc<RwLock<Arc<Node>>>,

    // percentage of nodes that need to agree for it to be deemed a majority
    majority_percentage: f32, // 0.1..0.9

    payload_ids: Mutex<HashMap<String, PayloadBuild>>,

    // setting to set if node timings are displayed
    node_timings_enabled: bool,

    // for if we want to use a general jwt with /create_node
    general_jwt: Option<JwtKey>,
    general_timeout: Option<Duration>,
}

impl NodeRouter {
    async fn authenticates(&self, authorization: &str) -> bool {
        if let Some(key) = &self.general_jwt {
            return key.verifies(authorization);
        }
        self.nodes
            .lock()
            .await
            .iter()
            .any(|node| node.jwt_key.verifies(authorization))
    }

    fn new(
        majority_percentage: f32,
        nodes: Vec<Arc<Node>>,
        primary_node: Arc<Node>,
        node_timings_enabled: bool,
        general_jwt: Option<JwtKey>,
        general_timeout: Option<Duration>,
    ) -> Self {
        NodeRouter {
            nodes: Arc::new(Mutex::new(nodes.clone())),
            alive_nodes: Arc::new(RwLock::new(Vec::new())),
            dead_nodes: Arc::new(RwLock::new(Vec::new())),
            alive_but_syncing_nodes: Arc::new(RwLock::new(Vec::new())),
            primary_node: Arc::new(RwLock::new(primary_node)),
            payload_ids: Mutex::new(HashMap::new()),
            majority_percentage,
            node_timings_enabled,
            general_jwt,
            general_timeout,
        }
    }

    // returns Vec<T> where it tries to deserialize for each resp to T
    async fn concurrent_requests<T>(
        &self,
        request: &RpcRequest,
        use_syncing_nodes: bool,
    ) -> (Vec<(Arc<Node>, T)>, Option<serde_json::Value>)
    where
        T: serde::de::DeserializeOwned,
    {
        let mut syncing_size: usize = 0;
        let mut nodes = self.alive_nodes.read().await.clone();

        if use_syncing_nodes {
            let mut syncing_nodes = self.alive_but_syncing_nodes.read().await.clone();
            syncing_size += syncing_nodes.len();
            nodes.append(&mut syncing_nodes);
        }

        let mut futs = Vec::with_capacity(nodes.len() + syncing_size);

        nodes.iter().for_each(|node| {
            futs.push(async {
                let start = std::time::Instant::now();
                let response = node.do_request(request).await;
                let resp_time = start.elapsed().as_millis();
                (response, node.clone(), resp_time)
            })
        });

        let mut out = Vec::with_capacity(nodes.len());
        let mut rpc_failure = None;
        let completed: Vec<(Result<String, reqwest::Error>, Arc<Node>, u128)> =
            join_all(futs).await;

        for resp_nodeurl_timing in completed {
            tracing::debug!(
                "Response from node {} took {}ms",
                resp_nodeurl_timing.1.url,
                resp_nodeurl_timing.2
            );
            match resp_nodeurl_timing.0 {
                Ok(resp_string) => {
                    // Preserve protocol errors when no EL can process this version.
                    if let Ok(response) = serde_json::from_str::<serde_json::Value>(&resp_string) {
                        if let Some(error) = response.get("error") {
                            if rpc_failure.is_none() {
                                rpc_failure = Some(error.clone());
                            }
                            continue;
                        }
                    }
                    let result = match parse_result(&resp_string) {
                        Ok(result) => result,
                        Err(e) => {
                            tracing::error!(
                                "Couldn't parse node result for {:?} from node {}: {:?}",
                                request.method,
                                resp_nodeurl_timing.1.url, // node url
                                e
                            );
                            continue;
                        }
                    };

                    match serde_json::from_value::<T>(result) {
                        Ok(deserialized) => {
                            out.push((resp_nodeurl_timing.1, deserialized));
                        }
                        Err(e) => {
                            tracing::error!(
                                "Couldn't deserialize response {:?} from node {} to type {}: {}",
                                request.method,
                                resp_nodeurl_timing.1.url, // node url
                                type_name::<T>(),
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "{:?} error from node {}: {}",
                        request.method,
                        resp_nodeurl_timing.1.url,
                        e
                    );
                }
            }
        }

        (out, rpc_failure)
    }

    async fn recheck(&self) {
        // check the status of all nodes
        // order nodes in alive_nodes vector by response time
        // dont clone nodes, just clone the Arcs

        let nodes = self.nodes.lock().await;
        let mut new_alive_nodes = Vec::<(u128, Arc<Node>)>::with_capacity(nodes.len()); // resp time, node
        let mut new_dead_nodes = Vec::<Arc<Node>>::with_capacity(nodes.len());
        let mut new_alive_but_syncing_nodes = Vec::<Arc<Node>>::with_capacity(nodes.len());

        let mut checks = Vec::new();

        for node in nodes.iter() {
            let check = async move {
                match node.check_status().await {
                    Ok(status) => (status, node.clone()),
                    Err(e) => {
                        if e.is_decode() {
                            tracing::error!(
                                "Error while checking node {}: {}; Maybe jwt related?",
                                node.url,
                                e
                            );
                        } else {
                            tracing::error!("Error while checking node {}: {}", node.url, e);
                        }

                        (
                            NodeHealth {
                                status: SyncingStatus::Offline,
                                resp_time: 0,
                            },
                            node.clone(),
                        )
                    }
                }
            };
            checks.push(check);
        }

        let results = join_all(checks).await;

        for (status, node) in results {
            if status.status == SyncingStatus::Synced {
                new_alive_nodes.push((status.resp_time, node.clone()));

                if self.node_timings_enabled {
                    tracing::info!("{}: {:.2}ms", node.url, (status.resp_time as f64 / 1000.0));
                    // resp_time is in micros
                }
            } else if status.status == SyncingStatus::OnlineAndSyncing {
                new_alive_but_syncing_nodes.push(node.clone());

                if self.node_timings_enabled {
                    tracing::info!("{}: {:.2}ms", node.url, (status.resp_time as f64 / 1000.0));
                }
            } else {
                new_dead_nodes.push(node.clone());
                if self.node_timings_enabled {
                    tracing::warn!("Dead node: {}", node.url);
                }
            }
        }

        // sort alive_nodes by response time
        new_alive_nodes.sort_by_key(|node| node.0);

        // update primary node to be the first alive node
        let mut primary_node = self.primary_node.write().await;
        *primary_node = match new_alive_nodes.first() {
            Some(node) => node.1.clone(),
            None => {
                // if there are no alive nodes, then set the primary node to a syncing node
                match new_alive_but_syncing_nodes.first() {
                    Some(node) => node.clone(),
                    None => {
                        // if there are no syncing nodes, then set the primary node to a dead node
                        match new_dead_nodes.first() {
                            Some(node) => node.clone(),
                            None => {
                                // if there are no dead nodes, then set the primary node to the first node
                                nodes[0].clone()
                            }
                        }
                    }
                }
            }
        };
        drop(primary_node);

        // lock alive_nodes, dead_nodes, and alive_but_syncing_nodes
        let mut alive_but_syncing_nodes = self.alive_but_syncing_nodes.write().await; // we have a hard time acquiring this lock for some reason
        let mut alive_nodes = self.alive_nodes.write().await;
        let mut dead_nodes = self.dead_nodes.write().await;

        // clear vectors and for alive nodes put the Arc<Node> in the vector
        alive_nodes.clear();
        dead_nodes.clear();
        alive_but_syncing_nodes.clear();

        for (_, node) in new_alive_nodes.iter() {
            alive_nodes.push(node.clone());
        }

        for node in new_dead_nodes.iter() {
            dead_nodes.push(node.clone());
        }

        for node in new_alive_but_syncing_nodes.iter() {
            alive_but_syncing_nodes.push(node.clone());
        }
    }

    // try and return the primary node asap
    // if the primary node is offline, then we'll get the next node in the vector, and set the primary node to that node (if its online)
    // basically, return the node closest to the start of the vector that is online, and set that as the primary node
    // if there are no online nodes, try to use a syncing node
    // if there are no syncing nodes, return None
    async fn get_execution_node(&self) -> Option<Arc<Node>> {
        let primary_node = self.primary_node.read().await.clone();

        if primary_node.status.read().await.status == SyncingStatus::Synced {
            return Some(primary_node.clone());
        }

        let old_primary_node_url = primary_node.url.clone(); // we're going to change it
        drop(primary_node);

        let alive_nodes = self.alive_nodes.read().await.clone();

        if alive_nodes.is_empty() {
            let alive_but_syncing_nodes = self.alive_but_syncing_nodes.read().await.clone();
            if alive_but_syncing_nodes.is_empty() {
                None
            } else {
                // no synced nodes, but there are syncing nodes, so return the first syncing node

                let node = alive_but_syncing_nodes[0].clone();
                let mut primary_node = self.primary_node.write().await;
                *primary_node = node.clone();
                Some(node)
            }
        } else {
            // there are synced nodes, so return the synced node (making sure its not the already checked primary node)
            for node in alive_nodes.iter() {
                if node.url != old_primary_node_url {
                    let node = node.clone();
                    let mut primary_node = self.primary_node.write().await;
                    *primary_node = node.clone();
                    return Some(node);
                }
            }
            // no synced nodes that are not the primary node, so return a syncing node
            let alive_but_syncing_nodes = self.alive_but_syncing_nodes.read().await.clone();
            if alive_but_syncing_nodes.is_empty() {
                // no synced or syncing nodes, so return None
                None
            } else {
                // no synced nodes, but there are syncing nodes, so return the first syncing node

                let node = alive_but_syncing_nodes[0].clone();
                let mut primary_node = self.primary_node.write().await;
                *primary_node = node.clone();
                Some(node)
            }
        }
    }

    // Return the most common status when it meets the configured threshold.
    // Ties have no majority, regardless of hash-map iteration order.
    fn fcu_majority(&self, results: &mut [PayloadStatusV1]) -> Option<PayloadStatusV1> {
        let total_responses = results.len();
        let majority_count = (total_responses as f32 * self.majority_percentage).round() as usize;

        let validation_error = results
            .iter()
            .find(|x| x.validation_error.is_some())
            .cloned();

        // Create a hashmap to store response frequencies
        let mut response_counts: HashMap<&PayloadStatusV1, usize> = HashMap::new();

        for response in results.iter_mut() {
            response.validation_error = None; // so we compare status and latest valid hash
            *response_counts.entry(response).or_insert(0) += 1;
        }

        // Find the response with the most occurrences
        let mut majority_response = None;
        let mut max_count = 0;
        let mut tied = false;

        for (response, count) in response_counts.into_iter() {
            if count > max_count {
                majority_response = Some(response);
                max_count = count;
                tied = false;
            } else if count == max_count {
                tied = true;
            }
        }

        if tied {
            return None;
        }

        // Check if the majority count is greater than or equal to the required count
        if max_count >= majority_count {
            if let Some(mut maj_response) = majority_response.cloned() {
                match maj_response.status {
                    // Spec says there's only a reason on INVALID
                    PayloadStatusV1Status::Invalid | PayloadStatusV1Status::InvalidBlockHash => {
                        if let Some(validation_err) = validation_error {
                            maj_response.validation_error = validation_err.validation_error;
                        }
                    }
                    _ => {}
                }

                return Some(maj_response);
            }

            majority_response.cloned()
        } else {
            None
        }
    }

    async fn fcu_logic(
        &self,
        resps: &mut Vec<PayloadStatusV1>,
        req: &RpcRequest,
    ) -> Result<PayloadStatusV1, FcuLogicError> {
        // send to the syncing nodes to help them catch up with tokio::spawn so we don't have to wait for them
        let syncing_nodes = self.alive_but_syncing_nodes.clone();
        let req_clone = req.clone();
        tokio::spawn(async move {
            let syncing_nodes = syncing_nodes.read().await.clone();
            if syncing_nodes.is_empty() {
                return;
            }

            tracing::debug!(
                "Sending fcU or newPayload to {} syncing nodes",
                syncing_nodes.len()
            );

            join_all(
                syncing_nodes
                    .iter()
                    .map(|node| node.do_request_no_timeout(&req_clone)),
            )
            .await;
        });

        if resps.is_empty() {
            // no responses, so return SYNCING
            tracing::error!("No responses, returning SYNCING.");
            return Err(FcuLogicError::NoResponses);
        }

        let majority = match self.fcu_majority(resps) {
            Some(majority) => majority,
            None => {
                // no majority, so return SYNCING
                tracing::warn!("No majority, returning SYNCING.");
                return Err(FcuLogicError::NoMajority);
            }
        };

        match majority.status {
            PayloadStatusV1Status::Invalid | PayloadStatusV1Status::InvalidBlockHash => {
                // majority is INVALID, so return INVALID (to not go through the next parts of the algorithm)
                tracing::warn!(validation_error=?majority.validation_error, "Majority responses are INVALID");
                return Ok(majority); // return Ok since this is not an error
            }
            _ => {} // there still can be invalid in the individual responses
        }

        for resp in resps {
            // check if any of the responses are INVALID

            match resp.status {
                PayloadStatusV1Status::Invalid | PayloadStatusV1Status::InvalidBlockHash => {
                    // a response is INVALID. One node could be right, no risks, return syncing to stall CL
                    tracing::warn!(validation_error=?resp.validation_error, "At least one response was INVALID");
                    return Err(FcuLogicError::OneNodeIsInvalid);
                }
                _ => {}
            }
        }

        // majority is checked and either VALID or SYNCING
        if majority.status == PayloadStatusV1Status::Syncing {
            tracing::warn!("Majority is SYNCING");
        };

        Ok(majority)
    }

    async fn do_engine_route(&self, request: &RpcRequest) -> (String, u16) {
        match request.method {
            EngineMethod::engine_getPayloadV1
            | EngineMethod::engine_getPayloadV2
            | EngineMethod::engine_getPayloadV3
            | EngineMethod::engine_getPayloadV4
            | EngineMethod::engine_getPayloadV5
            | EngineMethod::engine_getPayloadV6 => {
                let id = request
                    .params
                    .as_array()
                    .filter(|p| p.len() == 1)
                    .and_then(|p| p[0].as_str())
                    .filter(|id| {
                        id.strip_prefix("0x")
                            .and_then(|v| hex::decode(v).ok())
                            .is_some_and(|v| v.len() == 8)
                    });
                let Some(id) = id else {
                    return (
                        rpc_error(&request.id, -32602, "Expected an 8-byte payload ID"),
                        200,
                    );
                };
                let nodes = {
                    let mut builds = self.payload_ids.lock().await;
                    builds.retain(|_, build| build.created.elapsed() < PAYLOAD_CACHE_TTL);
                    builds.get(id).map(|build| build.nodes.clone())
                };
                let Some(nodes) = nodes else {
                    return (rpc_error(&request.id, -38001, "Unknown payload"), 200);
                };
                let fork = match request.method {
                    EngineMethod::engine_getPayloadV1 => ForkName::Merge,
                    EngineMethod::engine_getPayloadV2 => ForkName::Shanghai,
                    EngineMethod::engine_getPayloadV3 => ForkName::Cancun,
                    EngineMethod::engine_getPayloadV4 => ForkName::Prague,
                    EngineMethod::engine_getPayloadV5 => ForkName::Osaka,
                    EngineMethod::engine_getPayloadV6 => ForkName::Amsterdam,
                    _ => unreachable!(),
                };
                let responses = join_all(
                    nodes
                        .into_iter()
                        .map(|node| node.get_payload(request.clone(), &fork)),
                )
                .await;
                let mut best: Option<PayloadCandidate> = None;
                let mut error = json!({"code": -38001, "message": "Unknown payload"});
                for response in responses {
                    match response {
                        Ok(candidate) => {
                            let replace = match &best {
                                Some(best) => candidate.block_value > best.block_value,
                                None => true,
                            };
                            if replace {
                                best = Some(candidate);
                            }
                        }
                        Err(failure) => error = failure,
                    }
                }
                if let Some(best) = best {
                    tracing::info!(
                        "{:?}: returning block #{} with value {} wei",
                        request.method,
                        best.block_number,
                        best.block_value
                    );
                    (make_response(&request.id, best.result), 200)
                } else {
                    (
                        json!({"jsonrpc":"2.0", "id":request.id, "error":error}).to_string(),
                        200,
                    )
                }
            }
            EngineMethod::engine_newPayloadV1
            | EngineMethod::engine_newPayloadV2
            | EngineMethod::engine_newPayloadV3
            | EngineMethod::engine_newPayloadV4
            | EngineMethod::engine_newPayloadV5 => {
                let payload = match parse_new_payload(request) {
                    Ok(payload) => payload,
                    Err(error) => return (rpc_error(&request.id, -32602, &error), 200),
                };
                let (responses, error) = self
                    .concurrent_requests::<PayloadStatusV1>(request, false)
                    .await;
                let mut statuses = responses.into_iter().map(|(_, status)| status).collect();
                match self.fcu_logic(&mut statuses, request).await {
                    Ok(status) => (make_response(&request.id, json!(status)), 200),
                    Err(FcuLogicError::NoResponses) if error.is_some() => (
                        json!({"jsonrpc":"2.0", "id":request.id, "error":error}).to_string(),
                        200,
                    ),
                    Err(_) => (make_syncing_str(request, Some(&payload)), 200),
                }
            }
            EngineMethod::engine_forkchoiceUpdatedV1
            | EngineMethod::engine_forkchoiceUpdatedV2
            | EngineMethod::engine_forkchoiceUpdatedV3
            | EngineMethod::engine_forkchoiceUpdatedV4 => {
                let count = if request.method == EngineMethod::engine_forkchoiceUpdatedV4 {
                    3
                } else {
                    2
                };
                let Some(params) = request.params.as_array().filter(|p| p.len() == count) else {
                    return (
                        rpc_error(&request.id, -32602, "Invalid forkchoiceUpdated params"),
                        200,
                    );
                };
                if count == 3
                    && !params[2].is_null()
                    && !params[2]
                        .as_str()
                        .and_then(|v| v.strip_prefix("0x"))
                        .and_then(|v| hex::decode(v).ok())
                        .is_some_and(|v| v.len() == 16)
                {
                    return (
                        rpc_error(
                            &request.id,
                            -32602,
                            "custodyColumns must be 16-byte DATA or null",
                        ),
                        200,
                    );
                }
                // Forward all params intact, including custodyColumns even with null attributes.
                let (responses, error) = self
                    .concurrent_requests::<forkchoiceUpdatedResponse>(request, false)
                    .await;
                let mut statuses = responses
                    .iter()
                    .map(|(_, response)| response.payloadStatus.clone())
                    .collect();
                let status = match self.fcu_logic(&mut statuses, request).await {
                    Ok(status) => status,
                    Err(FcuLogicError::NoResponses) if error.is_some() => {
                        return (
                            json!({"jsonrpc":"2.0", "id":request.id, "error":error}).to_string(),
                            200,
                        )
                    }
                    Err(_) => return (make_syncing_str(request, None), 200),
                };
                let mut payload_id = None;
                if !params[1].is_null() && status.status == PayloadStatusV1Status::Valid {
                    let nodes: Vec<_> = responses
                        .into_iter()
                        .filter_map(|(node, response)| {
                            if response.payloadStatus.status != PayloadStatusV1Status::Valid {
                                return None;
                            }
                            response
                                .payloadId
                                .filter(|id| {
                                    id.strip_prefix("0x")
                                        .and_then(|v| hex::decode(v).ok())
                                        .is_some_and(|v| v.len() == 8)
                                })
                                .map(|payload_id| PayloadIdNode { node, payload_id })
                        })
                        .collect();
                    if !nodes.is_empty() {
                        let mut builds = self.payload_ids.lock().await;
                        builds.retain(|_, build| build.created.elapsed() < PAYLOAD_CACHE_TTL);
                        if builds.len() >= MAX_PAYLOAD_BUILDS {
                            if let Some(oldest) = builds
                                .iter()
                                .min_by_key(|(_, build)| build.created)
                                .map(|(id, _)| id.clone())
                            {
                                builds.remove(&oldest);
                            }
                        }
                        let id = loop {
                            let mut bytes = [0; 8];
                            rand::thread_rng().fill_bytes(&mut bytes);
                            let id = format!("0x{}", hex::encode(bytes));
                            if !builds.contains_key(&id) {
                                break id;
                            }
                        };
                        builds.insert(
                            id.clone(),
                            PayloadBuild {
                                created: std::time::Instant::now(),
                                nodes,
                            },
                        );
                        payload_id = Some(id);
                    }
                }
                (
                    make_response(
                        &request.id,
                        json!(forkchoiceUpdatedResponse {
                            payloadStatus: status,
                            payloadId: payload_id
                        }),
                    ),
                    200,
                )
            }
            EngineMethod::engine_exchangeCapabilities => {
                // Intersect responding voting ELs and methods understood here. An
                // offline EL must not disable the capabilities of working backups.
                let nodes: Vec<_> = self
                    .nodes
                    .lock()
                    .await
                    .iter()
                    .filter(|n| !n.do_not_use)
                    .cloned()
                    .collect();
                let replies = join_all(nodes.iter().map(|node| node.do_request(request))).await;
                let mut common: Option<Vec<String>> = None;
                for reply in replies {
                    let Ok(body) = reply else {
                        continue;
                    };
                    let methods = parse_result(&body)
                        .ok()
                        .and_then(|result| serde_json::from_value::<Vec<String>>(result).ok())
                        .unwrap_or_default();
                    let supported: Vec<_> = methods
                        .into_iter()
                        .filter(|name| serde_json::from_value::<EngineMethod>(json!(name)).is_ok())
                        .collect();
                    match common.as_mut() {
                        None => common = Some(supported),
                        Some(common) => common.retain(|name| supported.contains(name)),
                    }
                }
                let mut common = common.unwrap_or_default();
                common.sort();
                common.dedup();
                (make_response(&request.id, json!(common)), 200)
            }
            EngineMethod::engine_getClientVersionV1 => {
                let (responses, _) = self
                    .concurrent_requests::<Vec<serde_json::Value>>(request, true)
                    .await;
                (
                    make_response(
                        &request.id,
                        json!(responses
                            .into_iter()
                            .flat_map(|(_, versions)| versions)
                            .collect::<Vec<_>>()),
                    ),
                    200,
                )
            }
            EngineMethod::engine_exchangeTransitionConfigurationV1
            | EngineMethod::engine_getPayloadBodiesByHashV1
            | EngineMethod::engine_getPayloadBodiesByRangeV1
            | EngineMethod::engine_getPayloadBodiesByHashV2
            | EngineMethod::engine_getPayloadBodiesByRangeV2
            | EngineMethod::engine_getBlobsV1
            | EngineMethod::engine_getBlobsV2
            | EngineMethod::engine_getBlobsV3
            | EngineMethod::engine_getBlobsV4 => {
                let Some(node) = self.get_execution_node().await else {
                    return (make_error(&request.id, "No nodes available"), 200);
                };
                match node.do_request_no_timeout(request).await {
                    Ok(response) => (response, 200),
                    Err(error) => (make_error(&request.id, &error.to_string()), 200),
                }
            }
        }
    }

    async fn do_route_normal(&self, request: String) -> (String, u16) {
        // simply send request to primary node
        let primary_node = match self.get_execution_node().await {
            Some(primary_node) => primary_node,
            None => {
                tracing::warn!("No primary node available for normal request");
                let id = match serde_json::from_str::<RpcRequest>(&request) {
                    Ok(request) => request.id,
                    Err(e) => {
                        tracing::error!("Error deserializing request: {}", e);
                        return (make_error(&0, &e.to_string()), 200);
                    }
                };
                return (make_error(&id, "No nodes available"), 500);
            }
        };

        let resp = primary_node.do_request_no_timeout_str(request).await;
        match resp {
            Ok(resp) => (resp, 200),
            Err(e) => (make_error(&1, &e.to_string()), 200),
        }
    }
}

// func to take body and headers from a request and return a string
async fn route_all(
    headers: HeaderMap,
    Extension(router): Extension<Arc<NodeRouter>>,
    body: String,
) -> impl IntoResponse {
    let j: serde_json::Value = match serde_json::from_str(&body) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("Couldn't deserialize request. Error: {}. Body: {}", e, body);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(rpc_error(&serde_json::Value::Null, -32700, "Invalid JSON"))
                .unwrap();
        }
    };

    let meth = match j["method"].as_str() {
        Some(meth) => meth,
        None => {
            tracing::error!("Request has no method field");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(rpc_error(&j["id"], -32600, "Request has no method field"))
                .unwrap();
        }
    };

    tracing::debug!("Request received, method: {}", j["method"]);

    if meth.starts_with("engine_") {
        tracing::trace!("Routing {} to engine route", j["method"]);

        let request: RpcRequest = match serde_json::from_str(&body) {
            Ok(request) => request,
            Err(e) => {
                tracing::error!("Error deserializing {} request: {}", j["method"], e);
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(rpc_error(
                        &j["id"],
                        if serde_json::from_value::<EngineMethod>(j["method"].clone()).is_err() {
                            -32601
                        } else {
                            -32602
                        },
                        "Unsupported method or invalid request",
                    ))
                    .unwrap();
            }
        };

        let jwt_token = match headers.get("Authorization") {
            Some(jwt_token) => match jwt_token.to_str() {
                Ok(jwt_token) => jwt_token,
                Err(e) => {
                    tracing::error!("Error while converting jwt token to string: {}", e);
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(
                            make_error(&0, "Error while converting jwt token to string")
                                .to_string(),
                        )
                        .unwrap();
                }
            },
            None => {
                tracing::error!("Request has no Authorization header");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(make_error(&0, "Request has no Authorization header").to_string())
                    .unwrap();
            }
        };

        // Backend tokens are signed per node, so authenticate the CL before
        // substituting any backend credential.
        if !router.authenticates(jwt_token).await {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(make_error(&request.id, "Invalid or expired JWT"))
                .unwrap();
        }

        let (resp, status) = router.do_engine_route(&request).await;

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(resp)
            .unwrap()
    }
    // engine requests
    else {
        tracing::trace!("Routing to normal route");

        let jwt_token = headers.get("Authorization");
        if jwt_token.is_none() {
            // Preserve unauthenticated non-engine RPC support for existing users.
            let (resp, status) = router.do_route_normal(body).await;

            return Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(resp)
                .unwrap();
        }

        let jwt_token = match headers.get("Authorization") {
            Some(header_value) => match header_value.to_str() {
                Ok(jwt_str) => jwt_str.to_string(),
                Err(e) => {
                    tracing::warn!(
                        "Could not extract authorization header from normal request: {}",
                        e
                    );
                    return Response::builder()
                        .status(400)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(r#"{"error": "Could not extract authorization header from normal request}"#.to_string())
                        .unwrap();
                }
            },
            None => {
                // should never happen, should've been caught before and been replaced
                return Response::builder()
                    .status(400)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(
                        r#"{"error": "This should never happen, please open an issue.}"#
                            .to_string(),
                    )
                    .unwrap();
            }
        };

        if !router.authenticates(&jwt_token).await {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(make_error(&j["id"], "Invalid or expired JWT"))
                .unwrap();
        }
        let (resp, status) = router.do_route_normal(body).await;

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(resp)
            .unwrap()
    } // all other non-engine requests
}

async fn make_metrics_report(
    router: Arc<NodeRouter>,
) -> Result<serde_json::Value, serde_json::Error> {
    // Release each list guard before acquiring another. Recheck writes these
    // lists together; retaining a read guard here can invert its lock order.
    let syncing_nodes = router.alive_but_syncing_nodes.read().await.clone();
    let alive_nodes = router.alive_nodes.read().await.clone();
    let dead_nodes = router.dead_nodes.read().await.clone();
    let primary_node = router.primary_node.read().await.url.clone();
    let resp_times: HashMap<String, u128> = join_all(
        syncing_nodes
            .iter()
            .chain(&alive_nodes)
            .map(|node| async move { (node.url.clone(), node.status.read().await.resp_time) }),
    )
    .await
    .into_iter()
    .collect();

    let metrics_report = MetricsReport {
        response_times: resp_times,
        alive_nodes: alive_nodes.iter().map(|node| node.url.clone()).collect(),
        syncing_nodes: syncing_nodes.iter().map(|node| node.url.clone()).collect(),
        dead_nodes: dead_nodes.iter().map(|node| node.url.clone()).collect(),
        primary_node,
    };

    serde_json::to_value(metrics_report)
}

async fn metrics(Extension(router): Extension<Arc<NodeRouter>>) -> impl IntoResponse {
    let report = match make_metrics_report(router).await {
        Ok(report) => report,
        Err(e) => {
            tracing::error!("Could not make metrics report: {}", e);
            json!({"error": format!("Could not make metrics report: {}", e)})
        }
    };

    let resp_body = match serde_json::to_string(&report) {
        Ok(resp_body) => resp_body,
        Err(e) => {
            tracing::error!("Unable to serialize metrics report: {}", e);
            r#"{"error":"Unable to serialize metrics report"}"#.to_string()
        }
    };

    Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "application/json")
        .body(resp_body)
        .unwrap()
}

// calls router.recheck, returns recheck time, and metrics
async fn recheck(router: Arc<NodeRouter>) -> Result<(String, StatusCode), String> {
    let start = std::time::Instant::now();
    router.recheck().await;
    let resp_time = start.elapsed().as_micros();

    let mut report = match make_metrics_report(router).await {
        Ok(report) => report,
        Err(e) => {
            tracing::error!("Unable to get metrics report: {}", e);
            return Err(
                r#"{"error":"Unable to get metrics report; Recheck succeeded."}"#.to_string(),
            );
        }
    };

    report["recheck_time"] = serde_json::to_value(resp_time).unwrap();

    let resp_body = match serde_json::to_string(&report) {
        Ok(resp_body) => resp_body,
        Err(e) => {
            tracing::error!("Unable to serialize metrics report: {}", e);
            return Err(r#"{"error":"Unable to serialize metrics report"}"#.to_string());
        }
    };

    Ok((resp_body, StatusCode::OK))
}

async fn recheck_handler(Extension(router): Extension<Arc<NodeRouter>>) -> impl IntoResponse {
    match recheck(router).await {
        Ok((resp_body, status_code)) => Response::builder()
            .status(status_code)
            .header(header::CONTENT_TYPE, "application/json")
            .body(resp_body)
            .unwrap(),
        Err(e) => Response::builder()
            .status(500)
            .header(header::CONTENT_TYPE, "application/json")
            .body(e)
            .unwrap(),
    }
}

async fn add_node(
    Extension(router): Extension<Arc<NodeRouter>>,
    extract::Json(request): extract::Json<NodeList>,
) -> impl IntoResponse {
    let mut nodes =
        match request.create_new_nodes(router.general_jwt.clone(), router.general_timeout) {
            Ok(nodes) => nodes,
            Err(e) => {
                tracing::error!("Unable to create nodes from NodeList: {}", e);
                return Response::builder()
                    .status(500)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(format!(
                        r#"{{"error":"Unable to get nodes from NodeList: {}"}}"#,
                        e
                    ))
                    .unwrap();
            }
        };

    tracing::info!("Adding {} new nodes", nodes.len());
    router.nodes.lock().await.append(&mut nodes);

    match recheck(router).await {
        Ok((resp_body, status_code)) => Response::builder()
            .status(status_code)
            .header(header::CONTENT_TYPE, "application/json")
            .body(resp_body)
            .unwrap(),
        Err(e) => Response::builder()
            .status(500)
            .header(header::CONTENT_TYPE, "application/json")
            .body(e)
            .unwrap(),
    }
}

#[tokio::main]
async fn main() {
    let matches = clap::App::new("executionbackup")
        .version(VERSION)
        .author("TennisBowling <tennisbowling@tennisbowling.com>")
        .setting(clap::AppSettings::ColoredHelp)
        .about("A Ethereum 2.0 multiplexer enabling execution node failover post-merge")
        .long_version(&*format!(
            "executionbackup version {} by TennisBowling <tennisbowling@tennisbowling.com>",
            VERSION
        ))
        .arg(
            clap::Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .takes_value(true)
                .default_value("7000"),
        )
        .arg(
            clap::Arg::with_name("nodes")
                .short("n")
                .long("nodes")
                .value_name("NODES")
                .help("Comma-separated list of nodes to use")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("jwt-secret")
                .short("j")
                .long("jwt-secret")
                .value_name("JWT")
                .help("Path to a JWT secret file")
                .takes_value(true)
                .required(false),
        )
        .arg(
            clap::Arg::with_name("fcu-majority")
                .short("fcu")
                .long("fcu-majority")
                .value_name("FCU")
                .help("Threshold % (written like 0.1 for 10%) to call responses a majority from forkchoiceUpdated")
                .takes_value(true)
                .default_value("0.6"),
        )
        .arg(
            clap::Arg::with_name("timeout")
                .long("timeout")
                .help("Default timeout for all node requests")
                .takes_value(true)
                .default_value("7500")
        )
        .arg(
            clap::Arg::with_name("listen-addr")
                .short("addr")
                .long("listen-addr")
                .value_name("LISTEN")
                .help("Address to listen for requests on")
                .takes_value(true)
                .default_value("0.0.0.0"),
        )
        .arg(
            clap::Arg::with_name("log-level")
                .short("l")
                .long("log-level")
                .value_name("LOG")
                .help("Log level")
                .takes_value(true)
                .default_value("info"),
        )
        .arg(
            clap::Arg::with_name("node-timings")
                .long("node-timings")
                .help("Show node ping times")
        )
        .arg(
            clap::Arg::with_name("holesky")
                .long("holesky")
                .help("Label this instance as Holesky (fork rules are enforced by the clients)")
        )
        .arg(
            clap::Arg::with_name("sepolia")
                .long("sepolia")
                .help("Label this instance as Sepolia (fork rules are enforced by the clients)")
        )
        .get_matches();

    let port = matches.value_of("port").unwrap();
    let nodes = matches.value_of("nodes").unwrap();
    let jwt_secret_path = matches.value_of("jwt-secret");
    let fcu_majority = matches.value_of("fcu-majority").unwrap();
    let timeout = matches.value_of("timeout");
    let listen_addr = matches.value_of("listen-addr").unwrap();
    let log_level = matches.value_of("log-level").unwrap();
    let node_timings_enabled = matches.is_present("node-timings");
    let is_holesky = matches.is_present("holesky");
    let is_sepolia = matches.is_present("sepolia");

    // set log level with tracing subscriber
    let filter_string = format!("{},hyper=info", log_level);

    let filter = EnvFilter::try_new(filter_string).unwrap_or_else(|_| EnvFilter::new(log_level));

    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(filter)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Setting default subscriber failed");
    tracing::info!("Starting executionbackup version {VERSION}");

    tracing::info!("fcu invalid threshold set to: {}", fcu_majority);
    let fcu_majority = fcu_majority.parse::<f32>();
    let fcu_majority = match fcu_majority {
        Ok(fcu_majority) => {
            if !(0.0..=1.0).contains(&fcu_majority) {
                tracing::error!("fcu majority must be between 0.0 and 1.0");
                return;
            }
            fcu_majority
        }
        Err(e) => {
            tracing::error!("Error parsing fcu majority: {}", e);
            return;
        }
    };

    let nodes = nodes.split(',').collect::<Vec<&str>>();
    let mut nodesinstances: Vec<Arc<Node>> = Vec::new();

    let jwt_re = match Regex::new(r"#jwt-secret=([^#]*)") {
        Ok(re) => re,
        Err(e) => {
            tracing::error!("Failed to compile jwt matching regex: {}", e);
            return;
        }
    };

    let timeout_re = match Regex::new(r"#timeout=([^#]*)") {
        Ok(re) => re,
        Err(e) => {
            tracing::error!("Failed to compile timeout matching regex: {}", e);
            return;
        }
    };

    let mut general_jwt: Option<JwtKey> = None;
    if let Some(general_jwt_path) = jwt_secret_path {
        general_jwt = Some(match read_jwt(general_jwt_path) {
            Ok(general_jwt) => general_jwt,
            Err(e) => {
                tracing::error!("Error reading encoding general jwt: {}", e);
                return;
            }
        });
    }

    let mut general_timeout: Option<Duration> = None;
    if let Some(general_node_timeout) = timeout {
        let general_node_timeout = match general_node_timeout.parse::<u64>() {
            Ok(gnt) => gnt,
            Err(e) => {
                tracing::error!("Could not parse timeout as int: {}", e);
                return;
            }
        };
        general_timeout = Some(Duration::from_millis(general_node_timeout));
    }

    for node in nodes.clone() {
        let mut jwt_secret = None;
        let mut timeout_duration = None;

        if let Some(captures) = jwt_re.captures(node) {
            if let Some(jwt_path) = captures.get(1) {
                jwt_secret = Some(match read_jwt(jwt_path.as_str()) {
                    Ok(secret) => secret,
                    Err(e) => {
                        tracing::error!("Could not encode jwt secret: {}", e);
                        return;
                    }
                });
            }
        } else if let Some(general_jwt) = &general_jwt {
            jwt_secret = Some(general_jwt.clone());
        } else {
            tracing::error!(
                "Node {} doesn't have a general or node-specific jwt to use",
                node
            );
            return;
        }

        if let Some(captures) = timeout_re.captures(node) {
            if let Some(timeout_str) = captures.get(1) {
                timeout_duration = Some(match timeout_str.as_str().parse::<u64>() {
                    Ok(timeout) => Duration::from_millis(timeout),
                    Err(e) => {
                        tracing::error!("Could not parse timeout as int: {}", e);
                        return;
                    }
                });
            }
        } else if let Some(general_timeout) = &general_timeout {
            timeout_duration = Some(*general_timeout);
        } else {
            tracing::error!(
                "Node {} doesn't have a general or node-specific timeout to use",
                node
            );
            return;
        }

        let node_str = jwt_re.replace(node, "").to_string();
        let node_str = timeout_re.replace(&node_str, "").to_string();
        let do_not_use = node_str.contains("#do-not-use");
        let node_str = node_str.replace("#do-not-use", "");
        nodesinstances.push(Arc::new(Node::new(
            node_str,
            jwt_secret.unwrap(),
            timeout_duration.unwrap(),
            do_not_use,
        )));
    }

    // Retain the network flags for CLI compatibility. Protocol versions are
    // selected by the CL, so EB no longer maintains a separate fork schedule.
    match (is_holesky, is_sepolia) {
        (true, false) => {
            tracing::info!("Running on holesky testnet");
        }
        (false, true) => {
            tracing::info!("Running on sepolia testnet");
        }
        (false, false) => {
            tracing::info!("Running on mainnet");
        }
        (true, true) => {
            tracing::error!(
                "EB cannot be set to both holesky and sepolia testnets. Please choose one."
            );
            return;
        }
    };

    // guarenteed to have at least 1 node since clap enforces it
    let primary_node = nodesinstances.first().unwrap().clone();

    let router = Arc::new(NodeRouter::new(
        fcu_majority,
        nodesinstances,
        primary_node,
        node_timings_enabled,
        general_jwt,
        general_timeout,
    ));

    // setup backround task to check if nodes are alive
    let router_clone = router.clone();
    tracing::debug!("Starting background recheck task");
    tokio::spawn(async move {
        loop {
            router_clone.recheck().await;
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });

    // setup axum server
    let app = Router::new()
        .route("/", axum::routing::post(route_all))
        .route("/metrics", axum::routing::get(metrics))
        .route("/recheck", axum::routing::get(recheck_handler))
        .route("/add_nodes", axum::routing::post(add_node))
        .layer(Extension(router.clone()))
        .layer(DefaultBodyLimit::disable()); // no body limit since some requests can be quite large

    let addr = format!("{}:{}", listen_addr, port);
    let addr: SocketAddr = addr.parse().unwrap();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("Unable to bind to {}: {}", addr, e);
            return;
        }
    };
    tracing::info!("Listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod glamsterdam_tests {
    use super::*;
    use serde_json::Value;

    const AMSTERDAM_HASH: &str =
        "0xc492baef5336bc976cd5533bfb5933f975b3eda8d88653ceafcffeb4e709c4af";
    const PRAGUE_HASH: &str = "0xc53c05f024ebb8635c8ce11c86701fcedeb983f0e2b86da16878a920b4547f59";

    fn hash() -> String {
        format!("0x{}", "00".repeat(32))
    }

    // Synthetic hash vectors independently calculated with Python RLP and
    // PyCryptodome Keccak, using the EIP-7685/7928/7843 header field order.
    fn payload(amsterdam: bool) -> Value {
        let mut payload = json!({
            "parentHash": hash(), "feeRecipient": format!("0x{}", "00".repeat(20)),
            "stateRoot": hash(), "receiptsRoot": hash(),
            "logsBloom": format!("0x{}", "00".repeat(256)), "prevRandao": hash(),
            "blockNumber": "0x1", "gasLimit": "0xbebc200", "gasUsed": "0x0",
            "timestamp": "0x6ac4fd60", "extraData": "0x", "baseFeePerGas": "0x1",
            "blockHash": PRAGUE_HASH, "transactions": [], "withdrawals": [],
            "blobGasUsed": "0x0", "excessBlobGas": "0x0"
        });
        if amsterdam {
            payload["blockHash"] = json!(AMSTERDAM_HASH);
            payload["blockAccessList"] =
                json!("0xdcdb941111111111111111111111111111111111111111c0c101c0c0c0");
            payload["slotNumber"] = json!("0xac6000");
        }
        payload
    }

    fn request(method: &str, params: Value) -> RpcRequest {
        serde_json::from_value(
            json!({"jsonrpc":"2.0", "id":"cl-request", "method":method, "params":params}),
        )
        .unwrap()
    }

    fn legacy_payload(version: u8) -> Value {
        let mut payload = payload(false);
        if version < 3 {
            payload.as_object_mut().unwrap().remove("blobGasUsed");
            payload.as_object_mut().unwrap().remove("excessBlobGas");
        }
        if version == 1 {
            payload.as_object_mut().unwrap().remove("withdrawals");
        }
        payload
    }

    fn new_payload(amsterdam: bool) -> RpcRequest {
        request(
            if amsterdam {
                "engine_newPayloadV5"
            } else {
                "engine_newPayloadV4"
            },
            json!([payload(amsterdam), [], hash(), ["0x0001", "0x030203"]]),
        )
    }

    fn fcu(version: u8, attributes: bool) -> RpcRequest {
        let attributes = if attributes {
            let mut attributes = json!({"timestamp":"0x6ac4fd60", "prevRandao":hash(),
                "suggestedFeeRecipient":format!("0x{}", "11".repeat(20))});
            if version >= 2 {
                attributes["withdrawals"] = json!([]);
            }
            if version >= 3 {
                attributes["parentBeaconBlockRoot"] = json!(hash());
            }
            if version == 4 {
                attributes["slotNumber"] = json!("0xac6000");
                attributes["targetGasLimit"] = json!("0xbebc200");
            }
            attributes
        } else {
            Value::Null
        };
        let mut params = json!([{"headBlockHash":hash(), "safeBlockHash":hash(), "finalizedBlockHash":hash()}, attributes]);
        if version == 4 {
            params
                .as_array_mut()
                .unwrap()
                .push(json!("0x01000000000000000000000000000000"));
        }
        request(&format!("engine_forkchoiceUpdatedV{}", version), params)
    }

    fn status(status: &str) -> Value {
        json!({"status":status, "latestValidHash":if status == "VALID" { json!(hash()) } else { Value::Null }, "validationError":null})
    }

    fn fcu_result(status_name: &str, id: Value) -> Value {
        json!({"payloadStatus":status(status_name), "payloadId":id})
    }

    fn envelope(amsterdam: bool, value: &str) -> Value {
        json!({"executionPayload":payload(amsterdam), "blockValue":value,
            "blobsBundle":{"commitments":[], "proofs":[], "blobs":[]},
            "shouldOverrideBuilder":true, "executionRequests":["0x0001", "0x030203"],
            "clientExtension":{"preserve":true}})
    }

    struct MockEl {
        node: Arc<Node>,
        replies: Arc<Mutex<HashMap<String, Value>>>,
        seen: Arc<Mutex<Vec<Value>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockEl {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl MockEl {
        async fn new() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let secret = format!("{:032}", address.port());
            let replies = Arc::new(Mutex::new(HashMap::<String, Value>::new()));
            let seen = Arc::new(Mutex::new(Vec::new()));
            let node = Arc::new(Node::new(
                format!("http://{}", address),
                JwtKey::from_secret(secret.as_bytes()),
                Duration::from_millis(500),
                false,
            ));
            node.set_synced().await;
            let handler_replies = replies.clone();
            let handler_seen = seen.clone();
            let app = Router::new().route("/", axum::routing::post(move |headers: HeaderMap, extract::Json(body): extract::Json<Value>| {
                let replies = handler_replies.clone();
                let seen = handler_seen.clone();
                let secret = secret.clone();
                async move {
                    let bearer = headers.get("Authorization").unwrap().to_str().unwrap().strip_prefix("Bearer ").unwrap();
                    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
                    validation.required_spec_claims.clear();
                    validation.validate_exp = false;
                    // The inbound token deliberately differs from every backend secret.
                    assert!(jsonwebtoken::decode::<Claims>(bearer,
                        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()), &validation).is_ok());
                    seen.lock().await.push(body.clone());
                    let mut reply = replies.lock().await.get(body["method"].as_str().unwrap()).cloned()
                        .unwrap_or_else(|| json!({"error":{"code":-32601,"message":"Method not found"}}));
                    reply["jsonrpc"] = json!("2.0");
                    reply["id"] = body["id"].clone();
                    ([(header::CONNECTION, "close")], extract::Json(reply))
                }
            }));
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                node,
                replies,
                seen,
                task,
            }
        }

        async fn result(&self, method: &str, result: Value) {
            self.replies
                .lock()
                .await
                .insert(method.into(), json!({"result":result}));
        }

        async fn stop(&self) {
            self.task.abort();
            while !self.task.is_finished() {
                tokio::task::yield_now().await;
            }
        }

        async fn error(&self, method: &str, code: i32) {
            self.replies.lock().await.insert(
                method.into(),
                json!({"error":{"code":code,"message":"EL error","data":"preserve"}}),
            );
        }
    }

    async fn router(els: &[&MockEl]) -> NodeRouter {
        let nodes: Vec<_> = els.iter().map(|el| el.node.clone()).collect();
        let router = NodeRouter::new(0.6, nodes.clone(), nodes[0].clone(), false, None, None);
        *router.alive_nodes.write().await = nodes;
        router
    }

    async fn call(router: &NodeRouter, request: &RpcRequest) -> Value {
        let (body, code) = router.do_engine_route(request).await;
        assert_eq!(code, 200);
        let response: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(response["id"], request.id);
        assert_eq!(response["jsonrpc"], "2.0");
        response
    }

    #[tokio::test]
    async fn syncing_selection_does_not_hold_alive_lock_while_waiting() {
        let node = Arc::new(Node::new(
            "http://127.0.0.1".into(),
            JwtKey::from_secret(&[1; 32]),
            Duration::from_secs(1),
            false,
        ));
        node.set_online_and_syncing().await;
        let router = NodeRouter::new(0.6, vec![node.clone()], node.clone(), false, None, None);
        router
            .alive_but_syncing_nodes
            .write()
            .await
            .push(node.clone());

        // Reproduce recheck holding the syncing lock while it needs alive_nodes.
        let syncing_guard = router.alive_but_syncing_nodes.write().await;
        let selection = router.get_execution_node();
        tokio::pin!(selection);
        assert!(futures::poll!(&mut selection).is_pending());
        let alive_guard =
            tokio::time::timeout(Duration::from_millis(100), router.alive_nodes.write())
                .await
                .expect("routing retained alive_nodes while waiting for syncing_nodes");
        drop(alive_guard);
        drop(syncing_guard);
        assert_eq!(selection.await.unwrap().url, node.url);
    }

    #[test]
    fn header_hashes_include_requests_bal_and_slot() {
        for amsterdam in [false, true] {
            let req = new_payload(amsterdam);
            let parsed = parse_new_payload(&req).unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&make_syncing_str(&req, Some(&parsed))).unwrap()
                    ["result"]["status"],
                "SYNCING"
            );
            for field in if amsterdam {
                vec!["slotNumber", "blockAccessList"]
            } else {
                vec!["gasLimit"]
            } {
                let mut changed = req.clone();
                changed.params[0][field] = json!(if field == "blockAccessList" {
                    "0xc0"
                } else {
                    "0x2"
                });
                let parsed = parse_new_payload(&changed).unwrap();
                let response: Value =
                    serde_json::from_str(&make_syncing_str(&changed, Some(&parsed))).unwrap();
                assert_eq!(response["result"]["status"], "INVALID");
                assert!(response["result"]["latestValidHash"].is_null());
            }
            let mut changed = req.clone();
            changed.params[3] = json!([]);
            let parsed = parse_new_payload(&changed).unwrap();
            let response: Value =
                serde_json::from_str(&make_syncing_str(&changed, Some(&parsed))).unwrap();
            assert_eq!(response["result"]["status"], "INVALID");
        }
    }

    #[test]
    fn tied_votes_have_no_majority() {
        let node = Arc::new(Node::new(
            "http://127.0.0.1".into(),
            JwtKey::from_secret(&[1; 32]),
            Duration::from_secs(1),
            false,
        ));
        let router = NodeRouter::new(0.6, vec![node.clone()], node, false, None, None);
        for other in ["INVALID", "SYNCING", "ACCEPTED"] {
            let valid: PayloadStatusV1 = serde_json::from_value(status("VALID")).unwrap();
            let other: PayloadStatusV1 = serde_json::from_value(status(other)).unwrap();
            assert!(router
                .fcu_majority(&mut [valid.clone(), other.clone()])
                .is_none());
            assert!(router.fcu_majority(&mut [other, valid]).is_none());
        }
        let invalid: PayloadStatusV1 = serde_json::from_value(status("INVALID")).unwrap();
        assert_eq!(
            router
                .fcu_majority(&mut [invalid.clone(), invalid])
                .unwrap()
                .status,
            PayloadStatusV1Status::Invalid
        );
    }

    #[test]
    fn legacy_hash_failures_use_versioned_status_codes() {
        for (version, expected) in [(1, "INVALID_BLOCK_HASH"), (2, "INVALID")] {
            let req = request(
                &format!("engine_newPayloadV{}", version),
                json!([legacy_payload(version)]),
            );
            let parsed = parse_new_payload(&req).unwrap();
            let response: Value =
                serde_json::from_str(&make_syncing_str(&req, Some(&parsed))).unwrap();
            assert_eq!(response["result"]["status"], expected);
        }
    }

    #[tokio::test]
    async fn v6_selects_complete_payload_retries_and_survives_backend_failure() {
        let a = MockEl::new().await;
        let b = MockEl::new().await;
        let c = MockEl::new().await;
        a.result(
            "engine_forkchoiceUpdatedV4",
            fcu_result("VALID", json!("0x0101010101010101")),
        )
        .await;
        b.result(
            "engine_forkchoiceUpdatedV4",
            fcu_result("VALID", json!("0x0202020202020202")),
        )
        .await;
        c.result(
            "engine_forkchoiceUpdatedV4",
            fcu_result("SYNCING", Value::Null),
        )
        .await;
        a.result("engine_getPayloadV6", envelope(true, "0x10"))
            .await;
        b.result("engine_getPayloadV6", envelope(true, "0x100"))
            .await;
        let router = router(&[&a, &b, &c]).await;
        let fc = fcu(4, true);
        let response = call(&router, &fc).await;
        assert_eq!(response["result"]["payloadStatus"]["status"], "VALID");
        let id = response["result"]["payloadId"].clone();
        assert!(id.as_str().is_some());
        for el in [&a, &b, &c] {
            assert_eq!(el.seen.lock().await[0], serde_json::to_value(&fc).unwrap());
        }
        let get = request("engine_getPayloadV6", json!([id]));
        for _ in 0..2 {
            assert_eq!(call(&router, &get).await["result"], envelope(true, "0x100"));
        }
        assert_eq!(
            a.seen.lock().await[1]["params"],
            json!(["0x0101010101010101"])
        );
        assert_eq!(
            b.seen.lock().await[1]["params"],
            json!(["0x0202020202020202"])
        );
        assert_eq!(c.seen.lock().await.len(), 1);
        let mut malformed = envelope(true, "0x1000");
        malformed["executionPayload"]
            .as_object_mut()
            .unwrap()
            .remove("blockAccessList");
        b.result("engine_getPayloadV6", malformed).await;
        assert_eq!(call(&router, &get).await["result"], envelope(true, "0x10"));
        b.error("engine_getPayloadV6", -38001).await;
        assert_eq!(call(&router, &get).await["result"], envelope(true, "0x10"));
        a.error("engine_getPayloadV6", -38005).await;
        assert!(call(&router, &get).await.get("error").is_some());
        // Failed fetches must not consume the build ID.
        a.result("engine_getPayloadV6", envelope(true, "0x20"))
            .await;
        assert_eq!(call(&router, &get).await["result"], envelope(true, "0x20"));
        b.stop().await;
        assert_eq!(call(&router, &get).await["result"], envelope(true, "0x20"));
    }

    #[tokio::test]
    async fn legacy_payload_versions_remain_fetchable() {
        let el = MockEl::new().await;
        let router = router(&[&el]).await;
        for (fc_version, get_method, result) in [
            (3, "engine_getPayloadV5", envelope(false, "0x1")),
            (1, "engine_getPayloadV1", legacy_payload(1)),
            (
                1,
                "engine_getPayloadV2",
                json!({"executionPayload":legacy_payload(1), "blockValue":"0x1"}),
            ),
            (
                2,
                "engine_getPayloadV2",
                json!({"executionPayload":legacy_payload(2), "blockValue":"0x2"}),
            ),
        ] {
            el.result(
                &format!("engine_forkchoiceUpdatedV{}", fc_version),
                fcu_result("VALID", json!("0x1111111111111111")),
            )
            .await;
            el.result(get_method, result.clone()).await;
            let build = call(&router, &fcu(fc_version, true)).await;
            let get = request(get_method, json!([build["result"]["payloadId"]]));
            assert_eq!(call(&router, &get).await["result"], result);
        }
    }

    #[tokio::test]
    async fn new_payload_fanout_and_disagreement_preserve_protocol() {
        let a = MockEl::new().await;
        let b = MockEl::new().await;
        let c = MockEl::new().await;
        let router = router(&[&a, &b, &c]).await;
        let req = new_payload(true);
        for el in [&a, &b, &c] {
            el.result("engine_newPayloadV5", status("VALID")).await;
        }
        assert_eq!(call(&router, &req).await["result"]["status"], "VALID");
        for el in [&a, &b, &c] {
            assert_eq!(el.seen.lock().await[0], serde_json::to_value(&req).unwrap());
        }
        c.result("engine_newPayloadV5", status("INVALID")).await;
        assert_eq!(call(&router, &req).await["result"]["status"], "SYNCING");
        b.result("engine_newPayloadV5", status("INVALID")).await;
        assert_eq!(call(&router, &req).await["result"]["status"], "INVALID");
        router.alive_nodes.write().await.clear();
        assert_eq!(call(&router, &req).await["result"]["status"], "SYNCING");
    }

    #[tokio::test]
    async fn null_payload_ids_errors_and_custody_only_updates() {
        let el = MockEl::new().await;
        let router = router(&[&el]).await;
        for state in ["VALID", "SYNCING", "INVALID"] {
            el.result("engine_forkchoiceUpdatedV4", fcu_result(state, Value::Null))
                .await;
            let response = call(&router, &fcu(4, true)).await;
            assert!(response["result"]["payloadId"].is_null());
            assert_eq!(response["result"]["payloadStatus"]["status"], state);
            assert!(router.payload_ids.lock().await.is_empty());
        }
        el.result(
            "engine_forkchoiceUpdatedV4",
            fcu_result("VALID", Value::Null),
        )
        .await;
        let req = fcu(4, false);
        call(&router, &req).await;
        assert_eq!(
            el.seen.lock().await.last().unwrap(),
            &serde_json::to_value(&req).unwrap()
        );
        for (method, req) in [
            ("engine_forkchoiceUpdatedV4", fcu(4, true)),
            ("engine_newPayloadV5", new_payload(true)),
        ] {
            for code in [-38005, -32602, -38003] {
                el.error(method, code).await;
                let response = call(&router, &req).await;
                assert_eq!(response["error"]["code"], code);
                assert_eq!(response["error"]["data"], "preserve");
            }
        }
        router.alive_nodes.write().await.clear();
        let response = call(&router, &req).await;
        assert_eq!(response["result"]["payloadStatus"]["status"], "SYNCING");
        assert!(response["result"].get("payloadId").unwrap().is_null());
        assert!(response.get("payloadId").is_none());
    }

    #[tokio::test]
    async fn malformed_requests_return_rpc_errors_without_panics() {
        let el = MockEl::new().await;
        let router = router(&[&el]).await;
        for method in [
            "engine_getPayloadV6",
            "engine_forkchoiceUpdatedV4",
            "engine_newPayloadV5",
        ] {
            for params in [
                Value::Null,
                json!([]),
                json!([null]),
                json!({"payload":null}),
            ] {
                assert_eq!(
                    call(&router, &request(method, params)).await["error"]["code"],
                    -32602
                );
            }
        }
        for field in ["blockAccessList", "slotNumber"] {
            let mut req = new_payload(true);
            req.params[0].as_object_mut().unwrap().remove(field);
            assert_eq!(call(&router, &req).await["error"]["code"], -32602);
        }
        for requests in [
            json!(null),
            json!(["0x00"]),
            json!(["0x0301", "0x0001"]),
            json!(["0x0001", "0x0002"]),
        ] {
            let mut req = new_payload(true);
            req.params[3] = requests;
            assert_eq!(call(&router, &req).await["error"]["code"], -32602);
        }
        let mut req = fcu(4, false);
        req.params[2] = json!("0x01");
        assert_eq!(call(&router, &req).await["error"]["code"], -32602);
        assert_eq!(
            call(
                &router,
                &request("engine_getPayloadV6", json!(["0xffffffffffffffff"]))
            )
            .await["error"]["code"],
            -38001
        );
        assert!(el.seen.lock().await.is_empty());
    }

    #[tokio::test]
    async fn capabilities_filter_unknown_methods_and_intersect_backends() {
        let a = MockEl::new().await;
        let b = MockEl::new().await;
        a.result(
            "engine_exchangeCapabilities",
            json!([
                "engine_newPayloadV5",
                "engine_getPayloadV6",
                "engine_getBlobsV99"
            ]),
        )
        .await;
        b.result(
            "engine_exchangeCapabilities",
            json!(["engine_newPayloadV5", "engine_getBlobsV99"]),
        )
        .await;
        let router = router(&[&a, &b]).await;
        let req = request("engine_exchangeCapabilities", json!([[]]));
        assert_eq!(
            call(&router, &req).await["result"],
            json!(["engine_newPayloadV5"])
        );
        b.error("engine_exchangeCapabilities", -32601).await;
        assert_eq!(call(&router, &req).await["result"], json!([]));
        b.stop().await;
        assert_eq!(
            call(&router, &req).await["result"],
            json!(["engine_getPayloadV6", "engine_newPayloadV5"])
        );
    }

    #[tokio::test]
    async fn malformed_rpc_envelopes_keep_protocol_error_codes() {
        let node = Arc::new(Node::new(
            "http://127.0.0.1".into(),
            JwtKey::from_secret(&[1; 32]),
            Duration::from_secs(1),
            false,
        ));
        let router = Arc::new(NodeRouter::new(
            0.6,
            vec![node.clone()],
            node,
            false,
            None,
            None,
        ));
        for (body, code, id) in [
            ("{".to_owned(), -32700, Value::Null),
            (
                json!({"jsonrpc":"2.0","id":"missing-method"}).to_string(),
                -32600,
                json!("missing-method"),
            ),
            (
                json!({"jsonrpc":"2.0","id":"unsupported","method":"engine_unknown","params":[]})
                    .to_string(),
                -32601,
                json!("unsupported"),
            ),
        ] {
            let response = route_all(HeaderMap::new(), Extension(router.clone()), body)
                .await
                .into_response();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let response: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(response["error"]["code"], code);
            assert_eq!(response["id"], id);
        }
    }

    #[tokio::test]
    async fn cl_authentication_precedes_backend_token_substitution() {
        let el = MockEl::new().await;
        el.result("engine_newPayloadV5", status("VALID")).await;
        let mut router = router(&[&el]).await;
        let cl_key = JwtKey::from_secret(&[42; 32]);
        router.general_jwt = Some(cl_key.clone());
        let router = Arc::new(router);
        let request = new_payload(true);
        for token in ["not-a-token".into(), make_jwt(&el.node.jwt_key).unwrap()] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "Authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );
            let response = route_all(
                headers,
                Extension(router.clone()),
                serde_json::to_string(&request).unwrap(),
            )
            .await
            .into_response();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert!(el.seen.lock().await.is_empty());
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", make_jwt(&cl_key).unwrap())
                .parse()
                .unwrap(),
        );
        let response = route_all(
            headers,
            Extension(router),
            serde_json::to_string(&request).unwrap(),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["result"]["status"], "VALID");
        assert_eq!(el.seen.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn payload_cache_is_bounded_and_expired_ids_are_unknown() {
        let el = MockEl::new().await;
        el.result(
            "engine_forkchoiceUpdatedV4",
            fcu_result("VALID", json!("0x1111111111111111")),
        )
        .await;
        let router = router(&[&el]).await;
        for i in 0..MAX_PAYLOAD_BUILDS {
            router.payload_ids.lock().await.insert(
                format!("0x{:016x}", i),
                PayloadBuild {
                    created: std::time::Instant::now(),
                    nodes: vec![],
                },
            );
        }
        let response = call(&router, &fcu(4, true)).await;
        let id = response["result"]["payloadId"].as_str().unwrap();
        assert_eq!(router.payload_ids.lock().await.len(), MAX_PAYLOAD_BUILDS);
        router.payload_ids.lock().await.get_mut(id).unwrap().created =
            std::time::Instant::now() - PAYLOAD_CACHE_TTL;
        assert_eq!(
            call(&router, &request("engine_getPayloadV6", json!([id]))).await["error"]["code"],
            -38001
        );
    }

    #[tokio::test]
    async fn syncing_backends_receive_custody_updates() {
        let a = MockEl::new().await;
        let b = MockEl::new().await;
        a.result(
            "engine_forkchoiceUpdatedV4",
            fcu_result("VALID", Value::Null),
        )
        .await;
        b.result(
            "engine_forkchoiceUpdatedV4",
            fcu_result("SYNCING", Value::Null),
        )
        .await;
        let router = router(&[&a, &b]).await;
        router
            .alive_nodes
            .write()
            .await
            .retain(|node| node.url != b.node.url);
        router
            .alive_but_syncing_nodes
            .write()
            .await
            .push(b.node.clone());
        b.node.set_online_and_syncing().await;
        let req = fcu(4, false);
        assert_eq!(
            call(&router, &req).await["result"]["payloadStatus"]["status"],
            "VALID"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !b.seen.lock().await.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(b.seen.lock().await[0], serde_json::to_value(&req).unwrap());
    }

    #[tokio::test]
    async fn bodies_and_sparse_cells_are_forwarded_intact() {
        let el = MockEl::new().await;
        let router = router(&[&el]).await;
        for (method, params, result) in [
            (
                "engine_getBlobsV4",
                json!([[hash(), hash()], "0x03000000000000000000000000000000"]),
                json!([{"blob_cells":["0x1234",null],"proofs":["0x5678",null]},null]),
            ),
            (
                "engine_getPayloadBodiesByHashV2",
                json!([[hash(), hash()]]),
                json!([null,{"transactions":[],"withdrawals":[],"blockAccessList":"0xc0"}]),
            ),
            (
                "engine_getPayloadBodiesByRangeV2",
                json!(["0x1", "0x1"]),
                json!([{"transactions":[],"withdrawals":null,"blockAccessList":null}]),
            ),
        ] {
            el.result(method, result.clone()).await;
            let req = request(method, params);
            assert_eq!(call(&router, &req).await["result"], result);
            assert_eq!(
                el.seen.lock().await.last().unwrap(),
                &serde_json::to_value(&req).unwrap()
            );
        }
    }
}
