#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use ethereum_types::{Address, Signature, H256, H64, U256};
use jsonwebtoken::{DecodingKey, EncodingKey};
use metastruct::metastruct;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssz_types::{
    typenum::{U1048576, U1073741824},
    VariableList,
};
use std::{collections::HashMap, fmt::Debug, sync::Arc};
pub mod keccak;
use superstruct::superstruct;
pub mod node;
use lazy_static::lazy_static;
use node::*;
use regex::Regex;
use tokio::time::Duration;

const DEFAULT_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;

lazy_static! {
    static ref JWT_HEADER: jsonwebtoken::Header = jsonwebtoken::Header::new(DEFAULT_ALGORITHM);
}

pub fn parse_result(resp: &str) -> Result<serde_json::Value, ParseError> {
    let j = match serde_json::from_str::<serde_json::Value>(resp) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(reponse_body = ?resp, "Error deserializing response: {}", e);
            return Err(ParseError::InvalidJson);
        }
    };

    if let Some(error) = j.get("error") {
        tracing::error!(reponse_body = ?resp, "Response has error: {}", error);
        return Err(ParseError::ElError);
    }

    let result = match j.get("result") {
        Some(result) => result,
        None => {
            tracing::error!(reponse_body = ?resp, "Response has no result field");
            return Err(ParseError::MethodNotFound);
        }
    };

    Ok(result.clone())
}

#[derive(Clone)]
pub struct PayloadIdNode {
    pub node: Arc<Node>,
    pub payload_id: String,
}

pub struct PayloadCandidate {
    pub result: serde_json::Value,
    pub block_value: U256,
    pub block_number: u64,
}

impl PayloadIdNode {
    pub async fn get_payload(
        self,
        mut request: RpcRequest,
        fork: &ForkName,
    ) -> Result<PayloadCandidate, serde_json::Value> {
        request.params = json!([self.payload_id]);
        let invalid = |message: String| json!({"code": -32603, "message": message});
        let body = self
            .node
            .do_request_timeout(&request, Duration::from_millis(800))
            .await
            .map_err(|e| invalid(e.to_string()))?;
        let response: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| invalid(e.to_string()))?;
        if let Some(error) = response.get("error") {
            return Err(error.clone());
        }
        let result = response
            .get("result")
            .ok_or_else(|| invalid("Missing result".into()))?;
        // Validate the versioned envelope, but return the original JSON intact. This
        // keeps bundles, execution requests and client extensions with their payload.
        let parsed = match fork {
            ForkName::Merge => {
                serde_json::from_value::<ExecutionPayloadV1>(result.clone()).map(|_| ())
            }
            ForkName::Shanghai => serde_json::from_value::<getPayloadResponseV2>(result.clone())
                .map(|_| ())
                .or_else(|_| {
                    serde_json::from_value::<getPayloadResponseV1>(result.clone()).map(|_| ())
                }),
            ForkName::Cancun => {
                serde_json::from_value::<getPayloadResponseV3>(result.clone()).map(|_| ())
            }
            ForkName::Prague => {
                serde_json::from_value::<getPayloadResponseV4>(result.clone()).map(|_| ())
            }
            ForkName::Osaka => {
                serde_json::from_value::<getPayloadResponseV5>(result.clone()).map(|_| ())
            }
            ForkName::Amsterdam => {
                serde_json::from_value::<getPayloadResponseV6>(result.clone()).map(|_| ())
            }
        };
        parsed.map_err(|e| {
            invalid(format!(
                "Invalid getPayload response from {}: {}",
                self.node.url, e
            ))
        })?;
        let (block_value, number) = if matches!(fork, ForkName::Merge) {
            (U256::zero(), &result["blockNumber"])
        } else {
            (
                serde_json::from_value::<U256>(result["blockValue"].clone())
                    .map_err(|e| invalid(e.to_string()))?,
                &result["executionPayload"]["blockNumber"],
            )
        };
        let number: QuantityU64 =
            serde_json::from_value(number.clone()).map_err(|e| invalid(e.to_string()))?;
        Ok(PayloadCandidate {
            result: result.clone(),
            block_value,
            block_number: number.value,
        })
    }
}

pub fn make_jwt(jwt_key: &JwtKey) -> Result<String, jsonwebtoken::errors::Error> {
    let claim_inst = Claims {
        iat: chrono::Utc::now().timestamp(),
    };
    jsonwebtoken::encode(&JWT_HEADER, &claim_inst, &jwt_key.encoding)
}

#[derive(Clone)]
pub struct JwtKey {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKey {
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }

    pub fn verifies(&self, authorization: &str) -> bool {
        let Some(token) = authorization.strip_prefix("Bearer ") else {
            return false;
        };
        let mut validation = jsonwebtoken::Validation::new(DEFAULT_ALGORITHM);
        validation.required_spec_claims.clear();
        validation.required_spec_claims.insert("iat".into());
        validation.validate_exp = false;
        validation.validate_aud = false;
        jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)
            .is_ok_and(|token| token.claims.iat.abs_diff(chrono::Utc::now().timestamp()) <= 60)
    }
}

pub fn read_jwt(path: &str) -> Result<JwtKey, String> {
    let jwt_secret =
        std::fs::read_to_string(path).map_err(|e| format!("Error reading jwt file: {}", e))?;
    let jwt_secret = jwt_secret.trim().to_string();

    // check if jwt_secret starts with "0x" and remove it if it does
    let jwt_secret = jwt_secret
        .strip_prefix("0x")
        .unwrap_or(&jwt_secret)
        .to_string();

    Ok(JwtKey::from_secret(
        &hex::decode(jwt_secret).map_err(|e| format!("Could not decode JWT: {}", e))?,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PayloadStatusV1Status {
    Valid,
    Syncing,
    Invalid,
    Accepted,
    InvalidBlockHash,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatusV1 {
    pub status: PayloadStatusV1Status,
    pub latest_valid_hash: Option<H256>,
    pub validation_error: Option<String>,
}

impl PayloadStatusV1 {
    pub fn new_invalid(latest_valid_hash: H256, validation_error: String) -> Self {
        Self {
            status: PayloadStatusV1Status::Invalid,
            latest_valid_hash: Some(latest_valid_hash),
            validation_error: Some(validation_error),
        }
    }

    pub fn new_syncing() -> Self {
        Self {
            status: PayloadStatusV1Status::Syncing,
            latest_valid_hash: None,
            validation_error: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub index: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub enum ForkName {
    Merge,
    Shanghai,
    Cancun,
    Prague,
    Osaka,
    Amsterdam,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NewPayloadRequest {
    pub execution_payload: ExecutionPayload,
    pub expected_blob_versioned_hashes: Option<Vec<H256>>,
    pub parent_beacon_block_root: Option<H256>,
    pub execution_requests: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct QuantityU64 {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub value: u64,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DepositRequest {
    pub pubkey: Vec<u8>,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: Signature,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: Vec<u8>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

// TODO: take a look at this. also try to fix the Vec<u8> into a better type for this and Withdrawal + DepositRequests
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: Vec<u8>,
    pub target_pubkey: Vec<u8>,
}

// TODO: consider not using getter(copy) here. Not sure that we need the Result<T, E> instead of Result<&T, E>

#[superstruct(
    variants(V1, V2, V3, V4),
    variant_attributes(derive(Serialize, Deserialize, Clone), serde(rename_all = "camelCase"))
)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", untagged, deny_unknown_fields)]
pub struct ExecutionPayload {
    #[superstruct(getter(copy))]
    pub parent_hash: H256,
    #[superstruct(getter(copy))]
    pub fee_recipient: Address,
    #[superstruct(getter(copy))]
    pub state_root: H256,
    #[superstruct(getter(copy))]
    pub receipts_root: H256,
    #[serde(with = "serde_utils::hex_vec")]
    pub logs_bloom: Vec<u8>,
    #[superstruct(getter(copy))]
    pub prev_randao: H256,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub block_number: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    #[superstruct(getter(copy))]
    pub gas_limit: u64,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub gas_used: u64,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub timestamp: u64,
    #[serde(with = "serde_utils::hex_vec")]
    pub extra_data: Vec<u8>,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::u256_hex_be")]
    pub base_fee_per_gas: U256,
    #[superstruct(getter(copy))]
    pub block_hash: H256,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: VariableList<VariableList<u8, U1073741824>, U1048576>, // larger one is max bytes per transaction, smaller one is max transactions per payload
    #[superstruct(only(V2, V3, V4))]
    pub withdrawals: Vec<Withdrawal>,
    #[superstruct(only(V3, V4), partial_getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub blob_gas_used: u64,
    #[superstruct(only(V3, V4), partial_getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub excess_blob_gas: u64,
    #[superstruct(only(V4))]
    #[serde(with = "serde_utils::hex_vec")]
    pub block_access_list: Vec<u8>,
    #[superstruct(only(V4), partial_getter(copy))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub slot_number: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[metastruct(mappings(map_execution_block_header_fields_base(exclude(
    withdrawals_root,
    blob_gas_used,
    excess_blob_gas,
    parent_beacon_block_root,
    requests_hash,
    block_access_list_hash,
    slot_number
)),))]
pub struct ExecutionBlockHeader {
    pub parent_hash: H256,
    pub ommers_hash: H256,
    pub beneficiary: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Vec<u8>,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: H256,
    pub nonce: H64,
    pub base_fee_per_gas: U256,
    pub withdrawals_root: Option<H256>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<H256>,
    pub requests_hash: Option<H256>,
    pub block_access_list_hash: Option<H256>,
    pub slot_number: Option<u64>,
}

impl ExecutionBlockHeader {
    pub fn from_payload(
        payload: &ExecutionPayload,
        rlp_empty_list_root: H256,
        rlp_transactions_root: H256,
        rlp_withdrawals_root: Option<H256>,
        rlp_blob_gas_used: Option<u64>,
        rlp_excess_blob_gas: Option<u64>,
        rlp_parent_beacon_block_root: Option<H256>,
    ) -> Self {
        // Most of these field mappings are defined in EIP-3675 except for `mixHash`, which is
        // defined in EIP-4399.
        ExecutionBlockHeader {
            parent_hash: payload.parent_hash(),
            ommers_hash: rlp_empty_list_root,
            beneficiary: payload.fee_recipient(),
            state_root: payload.state_root(),
            transactions_root: rlp_transactions_root,
            receipts_root: payload.receipts_root(),
            logs_bloom: payload.logs_bloom().clone(),
            difficulty: U256::zero(),
            number: payload.block_number().into(),
            gas_limit: payload.gas_limit().into(),
            gas_used: payload.gas_used().into(),
            timestamp: payload.timestamp(),
            extra_data: payload.extra_data().clone(),
            mix_hash: payload.prev_randao(),
            nonce: H64::zero(),
            base_fee_per_gas: payload.base_fee_per_gas(),
            withdrawals_root: rlp_withdrawals_root,
            blob_gas_used: rlp_blob_gas_used,
            excess_blob_gas: rlp_excess_blob_gas,
            parent_beacon_block_root: rlp_parent_beacon_block_root,
            requests_hash: None,
            block_access_list_hash: payload
                .block_access_list()
                .ok()
                .map(|bal| H256(keccak::keccak256(bal).into())),
            slot_number: payload.slot_number().ok(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// issued-at claim. Represented as seconds passed since UNIX_EPOCH.
    pub iat: i64,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SyncingStatus {
    Synced,
    Offline,
    OnlineAndSyncing,
    NodeNotInitialized,
}

#[derive(Debug)]
pub enum FcuLogicError {
    NoMajority,
    OneNodeIsInvalid,
    NoResponses,
}

#[derive(Debug)]
pub enum ParseError {
    MethodNotFound,
    NoMethod,
    NoId,
    InvalidJson,
    NoParams,
    ElError,
}

pub struct NodeTiming {
    pub node: String,
    pub resp_time: u128,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum EngineMethod {
    engine_newPayloadV1,
    engine_forkchoiceUpdatedV1,
    engine_getPayloadV1,
    engine_exchangeTransitionConfigurationV1,
    engine_exchangeCapabilities,
    engine_newPayloadV2,
    engine_forkchoiceUpdatedV2,
    engine_getPayloadV2,
    engine_getPayloadBodiesByHashV1,
    engine_getPayloadBodiesByRangeV1,
    engine_newPayloadV3,
    engine_forkchoiceUpdatedV3,
    engine_getPayloadV3,
    engine_getClientVersionV1,
    engine_getBlobsV1,
    // prague
    engine_newPayloadV4,
    engine_getPayloadV4,
    // osaka
    engine_getBlobsV2,
    engine_getBlobsV3,
    engine_getPayloadV5,
    // amsterdam
    engine_newPayloadV5,
    engine_forkchoiceUpdatedV4,
    engine_getPayloadV6,
    engine_getPayloadBodiesByHashV2,
    engine_getPayloadBodiesByRangeV2,
    engine_getBlobsV4,
    // bogota
    engine_forkchoiceUpdatedV5,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RpcRequest {
    pub method: EngineMethod,
    pub params: serde_json::Value,
    pub id: serde_json::Value,
    pub jsonrpc: String,
}

impl RpcRequest {
    #[inline]
    pub fn as_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
pub struct forkchoiceUpdatedResponse<T = PayloadStatusV1> {
    pub payloadStatus: T,
    pub payloadId: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatusV2 {
    #[serde(flatten)]
    pub base: PayloadStatusV1,
    pub inclusion_list_satisfied: Option<bool>,
}

#[superstruct(
    variants(V1, V2, V3, V4, V5, V6),
    variant_attributes(derive(Serialize, Deserialize, Clone), serde(rename_all = "camelCase"))
)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", untagged)]
pub struct getPayloadResponse {
    #[superstruct(only(V1), partial_getter(rename = "execution_payload_v1"))] // V1, V2
    pub execution_payload: ExecutionPayloadV1,
    #[superstruct(only(V2), partial_getter(rename = "execution_payload_v2"))]
    pub execution_payload: ExecutionPayloadV2,
    #[superstruct(only(V3, V4, V5), partial_getter(rename = "execution_payload_v3"))]
    pub execution_payload: ExecutionPayloadV3,
    #[superstruct(only(V6), partial_getter(rename = "execution_payload_v4"))]
    pub execution_payload: ExecutionPayloadV4,
    #[serde(with = "serde_utils::u256_hex_be")]
    #[superstruct(partial_getter(copy), only(V1, V2, V3, V4, V5, V6))]
    pub block_value: U256,
    #[superstruct(only(V3, V4, V5, V6))]
    pub blobs_bundle: serde_json::Value,
    #[superstruct(only(V3, V4, V5, V6), partial_getter(copy))]
    pub should_override_builder: bool,
    #[superstruct(only(V4, V5, V6))]
    pub execution_requests: serde_json::Value,
}

impl Debug for getPayloadResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1(_) => f.debug_tuple("V1").finish(),
            Self::V2(_) => f.debug_tuple("V2").finish(),
            Self::V3(_) => f.debug_tuple("V3").finish(),
            Self::V4(_) => f.debug_tuple("V4").finish(),
            Self::V5(_) => f.debug_tuple("V5").finish(),
            Self::V6(_) => f.debug_tuple("V6").finish(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MetricsReport {
    pub response_times: HashMap<String, u128>,
    pub alive_nodes: Vec<String>,
    pub syncing_nodes: Vec<String>,
    pub dead_nodes: Vec<String>,
    pub primary_node: String,
}

#[derive(Serialize, Deserialize)]
pub struct NodeList {
    pub nodes: Vec<String>,
}

impl NodeList {
    pub fn from_nodes_vec(nodes_vec: &[Node]) -> Self {
        NodeList {
            nodes: nodes_vec.iter().map(|node| node.url.clone()).collect(),
        }
    }

    pub fn create_new_nodes(
        self,
        general_jwt: Option<JwtKey>,
        general_timeout: Option<Duration>,
    ) -> Result<Vec<Arc<Node>>, String> {
        let jwt_re = match Regex::new(r"#jwt-secret=([^#]*)") {
            Ok(re) => re,
            Err(e) => {
                tracing::error!("Failed to compile jwt matching secret: {}", e);
                return Err(format!("Failed to compile jwt matching secret: {}", e));
            }
        };

        let timeout_re = match Regex::new(r"#timeout=([^#]*)") {
            Ok(re) => re,
            Err(e) => {
                tracing::error!("Failed to compile timeout matching regex: {}", e);
                return Err(format!("Failed to compile timeout matching regex: {}", e));
            }
        };

        let mut nodeinstances: Vec<Arc<Node>> = Vec::with_capacity(self.nodes.len());

        for node in self.nodes {
            let mut jwt_secret = None;
            let mut timeout_duration = None;

            if let Some(captures) = jwt_re.captures(&node) {
                if let Some(jwt_path) = captures.get(1) {
                    jwt_secret = Some(match read_jwt(jwt_path.as_str()) {
                        Ok(secret) => secret,
                        Err(e) => {
                            tracing::error!("Could not encode jwt secret: {}", e);
                            return Err(format!("Could not encode jwt secret: {}", e));
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
                return Err(format!(
                    "Node {} doesn't have a general or node-specific jwt to use",
                    node
                ));
            }

            if let Some(captures) = timeout_re.captures(&node) {
                if let Some(timeout_str) = captures.get(1) {
                    timeout_duration = Some(match timeout_str.as_str().parse::<u64>() {
                        Ok(timeout) => Duration::from_millis(timeout),
                        Err(e) => {
                            tracing::error!("Could not parse timeout as int: {}", e);
                            return Err(format!("Could not parse timeout as int: {}", e));
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
                return Err(format!(
                    "Node {} doesn't have a general or node-specific timeout to use",
                    node
                ));
            }

            let node_str = jwt_re.replace(&node, "").to_string();
            let node_str = timeout_re.replace(&node_str, "").to_string();
            let do_not_use = node_str.contains("#do-not-use");
            let node_str = node_str.replace("#do-not-use", "");
            nodeinstances.push(Arc::new(Node::new(
                node_str,
                jwt_secret.unwrap(),
                timeout_duration.unwrap(),
                do_not_use,
            )));
        }

        Ok(nodeinstances)
    }
}

#[cfg(test)]
mod jwt_tests {
    use super::*;

    #[test]
    fn accepts_only_fresh_tokens_with_the_correct_signature() {
        let key = JwtKey::from_secret(&[1; 32]);
        assert!(key.verifies(&format!("Bearer {}", make_jwt(&key).unwrap())));
        assert!(!key.verifies("Bearer invalid"));
        assert!(
            !JwtKey::from_secret(&[2; 32]).verifies(&format!("Bearer {}", make_jwt(&key).unwrap()))
        );
        for offset in [-120, 120] {
            let token = jsonwebtoken::encode(
                &JWT_HEADER,
                &Claims {
                    iat: chrono::Utc::now().timestamp() + offset,
                },
                &key.encoding,
            )
            .unwrap();
            assert!(!key.verifies(&format!("Bearer {}", token)));
        }
    }
}
