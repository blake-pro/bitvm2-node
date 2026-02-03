#![allow(dead_code)]

use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::sol_types::SolValue;
use axum::{Json, Router, extract::State, routing::post};
use regex::Regex;
use std::sync::{Arc, Mutex};

use bitvm2_noded::utils::evm_swap_utils::IEscrowManager::EscrowData;
use store::localdb::StorageProcessor;
use store::{BridgeOutGlobalStats, GoatTxRecord, Graph, Instance, Message};
use uuid::Uuid;

/// Well-known test instance and graph IDs used in mock responses
#[allow(dead_code)]
pub mod test_fixtures {
    /// Standard test instance ID used in bridge-in tests and mock graph responses
    pub const BRIDGE_IN_INSTANCE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    /// Standard test graph ID used in bridge-out disprove tests
    pub const BRIDGE_OUT_GRAPH_ID: &str = "11111111-1111-1111-1111-111111111111";

    /// Get bridge_in instance ID as Uuid
    pub fn bridge_in_instance_id() -> uuid::Uuid {
        uuid::Uuid::parse_str(BRIDGE_IN_INSTANCE_ID).unwrap()
    }

    /// Get bridge_out graph ID as Uuid
    pub fn bridge_out_graph_id() -> uuid::Uuid {
        uuid::Uuid::parse_str(BRIDGE_OUT_GRAPH_ID).unwrap()
    }

    /// Format instance ID as hex without dashes (for mock responses)
    pub fn instance_id_hex() -> String {
        format!("0x{}", BRIDGE_IN_INSTANCE_ID.replace("-", ""))
    }

    /// Format graph ID as hex without dashes (for mock responses)
    pub fn graph_id_hex() -> String {
        format!("0x{}", BRIDGE_OUT_GRAPH_ID.replace("-", ""))
    }
}

#[derive(Clone, Default)]
pub struct GraphMockState {
    pub initializes: Option<serde_json::Value>,
    pub claims: Option<serde_json::Value>,
    pub refunds: Option<serde_json::Value>,
    pub bridge_in_requests: Option<serde_json::Value>,
    pub bridge_ins: Option<serde_json::Value>,
    pub committee_responses: Option<serde_json::Value>,
    pub init_withdraws: Option<serde_json::Value>,
    pub cancel_withdraws: Option<serde_json::Value>,
    pub proceed_withdraws: Option<serde_json::Value>,
    pub withdraw_happy_paths: Option<serde_json::Value>,
    pub withdraw_unhappy_paths: Option<serde_json::Value>,
    pub withdraw_disproveds: Option<serde_json::Value>,
    pub post_graph_datas: Option<serde_json::Value>,
}

pub type SharedGraphMockState = Arc<Mutex<GraphMockState>>;

#[derive(Clone)]
pub struct GraphMockAppState {
    pub state: SharedGraphMockState,
}

pub fn new_graph_mock_state() -> SharedGraphMockState {
    Arc::new(Mutex::new(GraphMockState::default()))
}

pub fn set_graph_mock_state(shared: &SharedGraphMockState, state: GraphMockState) {
    if let Ok(mut guard) = shared.lock() {
        *guard = state;
    }
}

pub fn clear_graph_mock_state(shared: &SharedGraphMockState) {
    set_graph_mock_state(shared, GraphMockState::default());
}

fn snapshot_graph_state(shared: &SharedGraphMockState) -> GraphMockState {
    shared.lock().map(|v| v.clone()).unwrap_or_default()
}

fn build_graph_mock_response(
    payload: serde_json::Value,
    state: GraphMockState,
) -> Json<serde_json::Value> {
    let query = payload.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let mut data = serde_json::Map::new();

    let instance_id_hex = test_fixtures::instance_id_hex();
    let graph_id_hex = test_fixtures::graph_id_hex();

    let escrow_data = EscrowData {
        offerer: Address::ZERO,
        claimer: Address::ZERO,
        amount: U256::from(100000),
        token: Address::ZERO,
        flags: U256::ZERO,
        claimHandler: Address::ZERO,
        claimData: B256::ZERO,
        refundHandler: Address::ZERO,
        refundData: B256::ZERO,
        securityDeposit: U256::ZERO,
        claimerBounty: U256::ZERO,
        depositToken: Address::ZERO,
        successActionCommitment: B256::ZERO,
    };
    let hash = keccak256(escrow_data.abi_encode());
    let hash_str = hex::encode(hash);

    let matches_query = |pattern: &str| -> bool {
        Regex::new(&format!(r"\b{}\b", pattern)).map(|re| re.is_match(query)).unwrap_or(false)
    };

    if matches_query("initializes") {
        let value = match state.initializes {
            Some(events) => events,
            None => serde_json::json!([
                {
                    "id": "init_1",
                    "transactionHash": "0xinit",
                    "blockNumber": "1",
                    "blockTimestamp": "1000",
                    "offerer": "0x0000000000000000000000000000000000000000",
                    "claimer": "0x0000000000000000000000000000000000000000",
                    "escrowHash": format!("0x{}", hash_str),
                    "claimHandler": "0x0000000000000000000000000000000000000000",
                    "refundHandler": "0x0000000000000000000000000000000000000000"
                }
            ]),
        };
        data.insert("initializes".to_string(), value);
    }

    if matches_query("claims") {
        let value = match state.claims {
            Some(events) => events,
            None => serde_json::json!([
                {
                    "id": "claim_1",
                    "transactionHash": "0xclaim",
                    "blockNumber": "2",
                    "blockTimestamp": "2000",
                    "offerer": "0x0000000000000000000000000000000000000000",
                    "claimer": "0x0000000000000000000000000000000000000000",
                    "escrowHash": format!("0x{}", hash_str),
                    "claimHandler": "0x0000000000000000000000000000000000000000",
                    "witnessResult": "0x"
                }
            ]),
        };
        data.insert("claims".to_string(), value);
    }

    if matches_query("refunds") {
        let value = match state.refunds {
            Some(events) => events,
            None => serde_json::json!([
                {
                    "id": "refund_1",
                    "transactionHash": "0xrefund",
                    "blockNumber": "3",
                    "offerer": "0x0000000000000000000000000000000000000000",
                    "claimer": "0x0000000000000000000000000000000000000000",
                    "escrowHash": format!("0x{}", hash_str),
                    "refundHandler": "0x0000000000000000000000000000000000000000",
                    "witnessResult": "0x"
                }
            ]),
        };
        data.insert("refunds".to_string(), value);
    }

    if matches_query("bridgeInRequests") {
        let value = match state.bridge_in_requests {
            Some(events) => events,
            None => serde_json::json!([
                {
                    "id": "test_id",
                    "transactionHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    "blockNumber": "10",
                    "blockTimestamp": "1600000000",
                    "instanceId": instance_id_hex,
                    "depositorAddress": "0x0000000000000000000000000000000000000100",
                    "peginAmountSats": "100000",
                    "txnFees": ["100", "100", "100"],
                    "userXonlyPubkey": "0xpubkey",
                    "userChangeAddress": "change_addr",
                    "userRefundAddress": "refund_addr"
                }
            ]),
        };
        data.insert("bridgeInRequests".to_string(), value);
    }

    if matches_query("bridgeIns") {
        let value = match state.bridge_ins {
            Some(events) => events,
            None => serde_json::json!([
                {
                    "id": "test_bridge_in",
                    "transactionHash": "0xbridge_in_tx_hash",
                    "blockNumber": "20",
                    "instanceId": instance_id_hex,
                    "depositorAddress": "0xdepositor",
                    "peginAmountSats": "100000",
                    "feeAmountSats": "1000"
                }
            ]),
        };
        data.insert("bridgeIns".to_string(), value);
    }

    if matches_query("committeeResponses") {
        let value = state.committee_responses.unwrap_or_else(|| serde_json::json!([]));
        data.insert("committeeResponses".to_string(), value);
    }

    if matches_query("initWithdraws") {
        let value = state.init_withdraws.unwrap_or_else(|| serde_json::json!([]));
        data.insert("initWithdraws".to_string(), value);
    }

    if matches_query("cancelWithdraws") {
        let value = state.cancel_withdraws.unwrap_or_else(|| serde_json::json!([]));
        data.insert("cancelWithdraws".to_string(), value);
    }

    if matches_query("proceedWithdraws") {
        let value = state.proceed_withdraws.unwrap_or_else(|| serde_json::json!([]));
        data.insert("proceedWithdraws".to_string(), value);
    }

    if matches_query("withdrawHappyPaths") {
        let value = state.withdraw_happy_paths.unwrap_or_else(|| serde_json::json!([]));
        data.insert("withdrawHappyPaths".to_string(), value);
    }

    if matches_query("withdrawUnhappyPaths") {
        let value = state.withdraw_unhappy_paths.unwrap_or_else(|| serde_json::json!([]));
        data.insert("withdrawUnhappyPaths".to_string(), value);
    }

    if matches_query("withdrawDisproveds") {
        let value = match state.withdraw_disproveds {
            Some(events) => events,
            None => serde_json::json!([
                {
                    "id": "test_disprove",
                    "transactionHash": "0xdisprove_tx_hash",
                    "blockNumber": "20",
                    "blockTimestamp": "1600000100",
                    "instanceId": instance_id_hex,
                    "graphId": graph_id_hex,
                    "disproveTxType": 1,
                    "txnIndex": "0",
                    "challengeStartTxid": "0xstart",
                    "challengeFinishTxid": "0xfinish",
                    "challengerAddress": "0x0000000000000000000000000000000000000001",
                    "disproverAddress": "0x0000000000000000000000000000000000000002",
                    "challengerRewardAmount": "1000",
                    "disproverRewardAmount": "1000"
                }
            ]),
        };
        data.insert("withdrawDisproveds".to_string(), value);
    }

    if matches_query("postGraphDatas") {
        let value = state.post_graph_datas.unwrap_or_else(|| serde_json::json!([]));
        data.insert("postGraphDatas".to_string(), value);
    }

    Json(serde_json::json!({
        "data": data
    }))
}

pub async fn mock_graph_handler(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    build_graph_mock_response(payload, GraphMockState::default())
}

pub async fn mock_graph_handler_with_state(
    State(app_state): State<GraphMockAppState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    build_graph_mock_response(payload, snapshot_graph_state(&app_state.state))
}

pub async fn start_mock_graph_server() -> String {
    let graph_router = Router::new().route("/", post(mock_graph_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let graph_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, graph_router).await.unwrap();
    });
    graph_url
}

pub async fn start_mock_graph_server_with_state(state: SharedGraphMockState) -> String {
    let graph_router = Router::new()
        .route("/", post(mock_graph_handler_with_state))
        .with_state(GraphMockAppState { state });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let graph_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, graph_router).await.unwrap();
    });

    graph_url
}

pub fn valid_btc_address() -> String {
    let compressed = bitcoin::CompressedPublicKey::from_slice(&[
        0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8,
        0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88, 0x7e,
        0x5b, 0x23, 0x52,
    ])
    .unwrap();

    bitcoin::Address::p2wpkh(&compressed, bitvm2_noded::env::get_network()).to_string()
}

pub async fn insert_instance(storage: &mut StorageProcessor<'_>, instance: &Instance) {
    storage.upsert_instance(instance).await.unwrap();
}

pub async fn insert_graph(storage: &mut StorageProcessor<'_>, graph: &Graph) {
    storage.upsert_graph(graph).await.unwrap();
}

pub async fn insert_goat_tx(storage: &mut StorageProcessor<'_>, record: &GoatTxRecord) {
    storage.upsert_goat_tx_record(record).await.unwrap();
}

pub async fn insert_message(storage: &mut StorageProcessor<'_>, message: &Message) {
    storage.upsert_message(message.clone()).await.unwrap();
}

pub async fn upsert_bridge_out_stats(
    storage: &mut StorageProcessor<'_>,
    stats: &BridgeOutGlobalStats,
) {
    storage.upsert_bridge_out_global_stats(stats).await.unwrap();
}

pub async fn get_instance(
    storage: &mut StorageProcessor<'_>,
    instance_id: &Uuid,
) -> Option<Instance> {
    storage.find_instance(instance_id).await.unwrap()
}

pub async fn get_graph(storage: &mut StorageProcessor<'_>, graph_id: &Uuid) -> Option<Graph> {
    storage.find_graph(graph_id).await.unwrap()
}

pub async fn get_goat_tx(
    storage: &mut StorageProcessor<'_>,
    instance_id: &Uuid,
    graph_id: &Uuid,
    tx_type: &str,
) -> Option<GoatTxRecord> {
    storage.find_graph_goat_tx_record(instance_id, graph_id, tx_type).await.unwrap()
}

pub async fn get_bridge_out_stats(storage: &mut StorageProcessor<'_>) -> BridgeOutGlobalStats {
    storage.find_bridge_out_global_stats_by_id(1).await.unwrap().unwrap_or_else(|| {
        BridgeOutGlobalStats {
            id: 1,
            initial_txn: 0,
            initial_amount: "0".to_string(),
            claim_txn: 0,
            claim_amount: "0".to_string(),
            refund_txn: 0,
            refund_amount: "0".to_string(),
            created_at: 0,
            updated_at: 0,
        }
    })
}
