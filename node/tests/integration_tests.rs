use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::rpc::types::trace::geth::{CallFrame, GethTrace};
use alloy::sol_types::SolCall;

use alloy::sol_types::SolValue;
use axum::{Json, Router, routing::post};
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, OutPoint, Transaction as BitcoinTransaction, TxOut as BitcoinTxOut, Txid as BitcoinTxid,
};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::types::UserInfo;
use bitvm2_noded::{
    env, rpc_service,
    scheduled_tasks::{
        event_watch_task,
        instance_maintenance_tasks::{
            instance_answers_monitor, instance_btc_tx_monitor, instance_expiration_monitor,
            instance_window_expiration_monitor,
        },
    },
    utils::{
        GenerateInstanceParams,
        evm_swap_utils::IEscrowManager::{self, EscrowData},
        store_pegin_request,
    },
};
use client::graphs::{
    GraphQueryClient,
    graph_query::{
        GatewayEventEntity, GatewayEventEntity::BridgeInRequests, GatewayEventEntity::BridgeIns,
        SwapEventEntity, TheGraphConfig, WatchEventConfig,
    },
};
use client::{
    btc_chain::{BTCClient, mock_bitcoin_adaptor::MockBitcoinAdaptor},
    goat_chain::{
        GOATClient, PeginData, PeginStatus, Utxo as GoatUtxo,
        mock_goat_adaptor::{GatewayContractConfig, MockAdaptor},
    },
};
use esplora_client::{Tx, TxStatus, Vout};
use goat::transactions::base::Input;
use regex::Regex;
use serial_test::serial;
use std::str::FromStr;
use std::{sync::Arc, time::Duration};
use store::{
    Graph, GraphStatus, Instance, InstanceBridgeInStatus, InstanceBridgeOutStatus,
    localdb::{InstanceQuery, InstanceUpdate},
};
use store::{create_local_db, localdb::LocalDB};
use tempfile::NamedTempFile;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Well-known test instance and graph IDs used in mock responses
#[allow(dead_code)]
mod test_fixtures {
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

#[allow(dead_code)]
mod test_helpers {
    use super::*;
    use store::localdb::StorageProcessor;

    // Re-export scopeguard::defer for tests needing RAII cleanup patterns
    #[allow(unused_imports)]
    pub use scopeguard::defer;

    /// Create a default EscrowData for bridge-out tests
    pub fn default_escrow_data() -> EscrowData {
        EscrowData {
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
        }
    }

    /// Create a confirmed TxStatus
    pub fn confirmed_tx_status(block_height: u32) -> TxStatus {
        TxStatus {
            confirmed: true,
            block_height: Some(block_height),
            block_hash: None,
            block_time: None,
        }
    }

    /// Create a mock Tx with optional confirmation
    pub fn mock_tx(txid: BitcoinTxid, block_height: Option<u32>) -> Tx {
        Tx {
            txid,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![],
            status: TxStatus {
                confirmed: block_height.is_some(),
                block_height,
                block_hash: None,
                block_time: None,
            },
            fee: 100,
            size: 100,
            weight: 400,
        }
    }

    /// Create a mock Tx with vouts
    pub fn mock_tx_with_vouts(txid: BitcoinTxid, block_height: u32, vouts: Vec<Vout>) -> Tx {
        Tx {
            txid,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vouts,
            status: confirmed_tx_status(block_height),
            fee: 100,
            size: 100,
            weight: 400,
        }
    }

    /// Start a mock graph server and return its URL
    pub async fn start_mock_graph_server() -> String {
        let graph_router = Router::new().route("/", post(super::mock_graph_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let graph_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, graph_router).await.unwrap();
        });
        graph_url
    }

    /// Assert instance has expected status
    pub async fn assert_instance_status(
        storage: &mut StorageProcessor<'_>,
        instance_id: &Uuid,
        expected: InstanceBridgeInStatus,
    ) {
        let instance = storage.find_instance(instance_id).await.unwrap().unwrap();
        assert_eq!(
            instance.status,
            expected.to_string(),
            "Expected status {:?}, got {}",
            expected,
            instance.status
        );
    }

    /// Assert graph has expected status
    pub async fn assert_graph_status(
        storage: &mut StorageProcessor<'_>,
        graph_id: &Uuid,
        expected: GraphStatus,
    ) {
        let graph = storage.find_graph(graph_id).await.unwrap().unwrap();
        assert_eq!(
            graph.status,
            expected.to_string(),
            "Expected graph status {:?}, got {}",
            expected,
            graph.status
        );
    }

    /// Create a valid test committee keypair
    pub fn test_committee_keypair() -> (bitcoin::PrivateKey, bitcoin::PublicKey) {
        let privkey =
            bitcoin::PrivateKey::from_slice(&[1u8; 32], bitcoin::Network::Regtest).unwrap();
        let pubkey = privkey.public_key(&bitcoin::secp256k1::Secp256k1::new());
        (privkey, pubkey)
    }

    /// Create a default PeginData for testing
    pub fn default_pegin_data(instance_id: Uuid, input_txid: [u8; 32]) -> PeginData {
        let (_privkey, pubkey) = test_committee_keypair();
        let committee_pubkey_bytes = pubkey.to_bytes();
        let committee_addr = [4u8; 20];

        PeginData {
            status: PeginStatus::Pending,
            instance_id: *instance_id.as_bytes(),
            depositor_address: [0u8; 20],
            pegin_amount_sats: 100000,
            txn_fees: [100, 100, 100],
            user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 200000 }],
            user_xonly_pubkey: [2u8; 32],
            user_change_addr: "bcrt1q...".to_string(),
            user_refund_addr: "bcrt1q...".to_string(),
            pegin_txid: [3u8; 32],
            created_at: 0,
            committee_addresses: vec![Address::from(committee_addr)],
            committee_pubkeys: vec![committee_pubkey_bytes],
        }
    }
}

async fn setup() -> (LocalDB, BTCClient, MockBitcoinAdaptor, GOATClient, MockAdaptor, NamedTempFile)
{
    // Set Env Vars for RPC start
    // SAFETY: Tests using this function must be marked with #[serial] to prevent
    // race conditions since environment variables are process-global state.
    unsafe {
        std::env::set_var("BTC_Node_URL", "http://127.0.0.1:18443");
        std::env::set_var("GOAT_CHAIN_URL", "http://127.0.0.1:8545");
        std::env::set_var(
            "GOAT_GATEWAY_CONTRACT_ADDRESS",
            "0x0000000000000000000000000000000000000000",
        );
    }

    // Setup LocalDB with temp file (file handle kept alive by caller)
    let db_file = NamedTempFile::new().unwrap();
    let db_path = db_file.path().to_str().unwrap().to_string();
    let local_db = create_local_db(&db_path).await;

    // Setup Mock BTC Client
    let (btc_client, btc_mock) = BTCClient::new_mock_client();

    // Setup Mock GOAT Client
    let (goat_client, goat_mock) = GOATClient::new_mock_client();

    // Default config for Goat mock
    goat_mock.set_gateway_contract_config(GatewayContractConfig {
        min_challenge_amount_sats: 100000,        // 0.01 BTC
        min_pegin_fee_sats: 5000,                 // 0.00005 BTC
        pegin_fee_rate: 50,                       // 0.5%
        min_operator_reward_sats: 3000,           // 0.00003 BTC
        operator_reward_rate: 30,                 // 0.3%
        min_stake_amount: 60000000000000000,      // 0.06 stakeToken(pegBTC)
        min_challenger_reward: 12500000000000000, // 0.0125 stakeToken(pegBTC)
        min_disprover_reward: 2500000000000000,   // 0.0025 stakeToken(pegBTC)
        min_slash_amount: 30000000000000000,      // 0.03 stakeToken(pegBTC)
    });

    (local_db, btc_client, btc_mock, goat_client, goat_mock, db_file)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_rpc_service_integration() {
    let (local_db, _, _, _, _, _db_file) = setup().await;
    let actor = Actor::Challenger;
    let peer_id = "test_peer_id".to_string();
    let registry = Arc::new(std::sync::Mutex::new(libp2p_metrics::Registry::default()));
    let cancel_token = CancellationToken::new();

    // Start Mock GOAT RPC (for chain_id)
    let goat_router = Router::new().route("/", post(mock_goat_rpc_handler));
    let goat_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let goat_addr = goat_listener.local_addr().unwrap();
    unsafe {
        std::env::set_var("GOAT_CHAIN_URL", format!("http://{goat_addr}"));
        std::env::remove_var("GOAT_GATEWAY_CONTRACT_ADDRESS"); // Skip contract checks
    }
    tokio::spawn(async move {
        axum::serve(goat_listener, goat_router).await.unwrap();
    });

    // Start RPC Service
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rpc_addr_str = addr.to_string();

    tokio::spawn(async move {
        rpc_service::serve(listener, local_db, actor, peer_id, registry, cancel_token)
            .await
            .unwrap();
    });

    // Wait for server start
    sleep(Duration::from_millis(500)).await;

    // Test /nodes endpoint
    let client = reqwest::Client::new();
    let resp = client.get(format!("http://{rpc_addr_str}/v1/nodes")).send().await;
    assert!(resp.is_ok());
    assert_eq!(resp.unwrap().status(), 200);
}

async fn mock_goat_rpc_handler(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let method = payload.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if method == "eth_chainId" {
        return Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": "0x7a69" // 31337
        }));
    }
    Json(serde_json::json!({"jsonrpc": "2.0", "id": payload.get("id"), "result": null}))
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_flow() {
    let (local_db, btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup().await;
    let actor = Actor::Challenger;
    let client = GraphQueryClient::new();

    // Start Mock Graph
    let graph_router = Router::new().route("/", post(mock_graph_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let graph_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, graph_router).await.unwrap();
    });

    let btc_client = Arc::new(btc_client);
    let goat_client = Arc::new(goat_client);
    let swap_contract_addr =
        Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let config_init = WatchEventConfig::Swap(TheGraphConfig {
        address: swap_contract_addr,
        the_graph_url: graph_url.clone(),
        event_entities: vec![SwapEventEntity::Initializes],
    });

    let mut storage_processor = local_db.acquire().await.unwrap();

    // 1. Prepare Data for Swap Initialize
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
    let escrow_hash = alloy::primitives::keccak256(escrow_data.abi_encode());

    // Mock Trace for Initialize
    let initialize_call = IEscrowManager::initializeCall {
        escrow: escrow_data.clone(),
        signature: Bytes::new(),
        timeout: U256::ZERO,
        _extraData: Bytes::new(),
    };
    let initialize_input = initialize_call.abi_encode(); // This includes selector

    let initialize_tx_hash = "0xinit";
    let trace = GethTrace::CallTracer(CallFrame {
        from: Address::ZERO,
        gas: U256::ZERO,
        gas_used: U256::ZERO,
        to: Some(swap_contract_addr),
        input: initialize_input.into(),
        output: Some(Bytes::new()),
        error: None,
        revert_reason: None,
        calls: vec![],
        logs: vec![],
        value: Some(U256::ZERO),
        typ: "CALL".to_string(),
    });
    goat_mock.set_trace(initialize_tx_hash.to_string(), trace);

    // Run Event Watch for Initialize
    event_watch_task::fetch_and_handle_block_range_events(
        actor.clone(),
        btc_client.clone(),
        goat_client.clone(),
        &client,
        &mut storage_processor,
        &config_init,
        0,
        100,
    )
    .await
    .unwrap();

    // Verify Instance Status = Initialize
    let (instances, _) = storage_processor
        .find_instances(
            InstanceQuery::default()
                .with_raw_condition(format!("escrow_hash = '0x{}'", hex::encode(escrow_hash.0))),
        )
        .await
        .unwrap();
    let instance = instances.first().expect("Instance not found");
    assert_eq!(instance.status, InstanceBridgeOutStatus::Initialize.to_string());
    assert_eq!(instance.bridge_out_amount, "100000");

    // 3. Prepare Data for Swap Claim
    let claim_tx_hash = "0xclaim";

    // Mock Trace for Claim
    // Claim needs witness data that parses into ClaimData
    // witness = txoHash || ...

    let mut witness = Vec::new();
    witness.extend_from_slice(&[0u8; 32]); // txoHash
    witness.extend_from_slice(&1u32.to_be_bytes()); // confirmations
    witness.extend_from_slice(&[0u8; 20]); // btcRelay
    witness.extend_from_slice(&[0u8; 160]); // blockheader
    witness.extend_from_slice(&0u32.to_be_bytes()); // vout

    // Tx
    let dummy_address = bitcoin::Address::p2pkh(
        bitcoin::PublicKey::from_slice(&[
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ])
        .unwrap(),
        bitcoin::Network::Regtest,
    );

    let tx = BitcoinTransaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn::default()],
        output: vec![BitcoinTxOut {
            value: Amount::from_sat(100000),
            script_pubkey: dummy_address.script_pubkey(),
        }],
    };
    let tx_bytes = bitcoin::consensus::serialize(&tx);
    let tx_len = U256::from(tx_bytes.len());
    witness.extend_from_slice(&tx_len.to_be_bytes::<32>());
    witness.extend_from_slice(&tx_bytes);

    let claim_call = IEscrowManager::claimCall { escrow: escrow_data, witness: witness.into() };
    let claim_input = claim_call.abi_encode();

    let trace_claim = GethTrace::CallTracer(CallFrame {
        from: Address::ZERO,
        gas: U256::ZERO,
        gas_used: U256::ZERO,
        to: Some(swap_contract_addr),
        input: claim_input.into(),
        output: Some(Bytes::new()),
        error: None,
        revert_reason: None,
        calls: vec![],
        logs: vec![],
        value: Some(U256::ZERO),
        typ: "CALL".to_string(),
    });
    goat_mock.set_trace(claim_tx_hash.to_string(), trace_claim);

    // Run Watch Task again for Claims
    let config_claim = WatchEventConfig::Swap(TheGraphConfig {
        address: swap_contract_addr,
        the_graph_url: graph_url.clone(),
        event_entities: vec![SwapEventEntity::Claims],
    });

    event_watch_task::fetch_and_handle_block_range_events(
        actor.clone(),
        btc_client.clone(),
        goat_client.clone(),
        &client,
        &mut storage_processor,
        &config_claim,
        101, // Next range
        200,
    )
    .await
    .unwrap();

    let (instances, _) = storage_processor
        .find_instances(
            InstanceQuery::default()
                .with_raw_condition(format!("escrow_hash = '0x{}'", hex::encode(escrow_hash.0))),
        )
        .await
        .unwrap();
    let instance = instances.first().expect("Instance not found");
    assert_eq!(instance.status, InstanceBridgeOutStatus::Claim.to_string());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_in_timeout() {
    let (local_db, btc_client, btc_mock, _, _, _db_file) = setup().await;

    // Create Instance in UserBroadcastPeginPrepare state
    let instance_id = Uuid::new_v4();
    let old_time = rpc_service::current_time_secs() - env::INSTANCE_PRESIGNED_TIME_EXPIRED - 1000;

    let mut storage_processor = local_db.acquire().await.unwrap();
    // Initialize required fields to avoid validation/DB errors
    let instance = store::Instance {
        instance_id,
        is_bridge_in: true,
        network: "regtest".to_string(),
        from_addr: "bcrt1q...".to_string(),
        to_addr: "0x...".to_string(),
        amount: 100000,
        status: InstanceBridgeInStatus::UserBroadcastPeginPrepare.to_string(),
        updated_at: old_time,
        created_at: old_time, // created long ago
        btc_height: 10,
        fees: Default::default(),
        input_utxos: "[]".to_string(),
        goat_tx_hash: "0x".to_string(),
        goat_tx_height: 0,
        user_xonly_pubkey: Default::default(),
        user_change_addr: "addr".to_string(),
        user_refund_addr: "addr".to_string(),
        btc_txid: None,
        pegin_confirm_txid: None,
        pegin_cancel_txid: None,
        committees_answers: Default::default(),
        pegin_data_tx_hash: "0x".to_string(),
        parameters: None,
        escrow_hash: None,
        bridge_out_lock_time: 0,
        post_pegin_txhash: None,
        bridge_out_amount: "0".to_string(),
        status_updated_at: old_time,
    };
    storage_processor.upsert_instance(&instance).await.unwrap();

    // 1. Run expiration monitor -> PresignedFailed (Time check)
    // Needs user Broadcast Pegin Prepare -> PresignedFailed if expired
    instance_expiration_monitor(&local_db, &btc_client).await.unwrap();

    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::PresignedFailed.to_string());

    // 2. Test PresignedFailed -> Timeout (Block height expiration)
    // lock_height = CONNECTOR_Z_TIMELOCK (approx 144)
    // current_height > btc_height (10) + lock_height
    btc_mock.set_height(1000); // 1000 > 10 + 144

    instance_expiration_monitor(&local_db, &btc_client).await.unwrap();

    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::Timeout.to_string());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_in_flow() {
    let (local_db, btc_client, btc_mock, goat_client, goat_mock, _db_file) = setup().await;
    let actor = Actor::Challenger;
    let client = GraphQueryClient::new();

    // Start a mock Graph Node server
    let graph_router = Router::new().route("/", post(mock_graph_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let graph_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, graph_router).await.unwrap();
    });

    // Wrap clients in Arc
    let btc_client = Arc::new(btc_client);
    let goat_client = Arc::new(goat_client);

    let default_config = WatchEventConfig::Gateway(TheGraphConfig {
        address: Address::ZERO, // Mock address
        the_graph_url: graph_url.clone(),
        event_entities: vec![BridgeInRequests],
    });

    let mut storage_processor = local_db.acquire().await.unwrap();

    // 1. Test BridgeInRequests -> UserInited
    event_watch_task::fetch_and_handle_block_range_events(
        actor.clone(),
        btc_client.clone(),
        goat_client.clone(),
        &client,
        &mut storage_processor,
        &default_config,
        0,
        100, // Block range
    )
    .await
    .unwrap();

    let instance_id = Uuid::from_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let tx_type = "BridgeInRequest";
    let record = storage_processor
        .find_graph_goat_tx_record(&instance_id, &Uuid::nil(), tx_type)
        .await
        .unwrap();

    assert!(record.is_some(), "GoatTxRecord not found for BridgeInRequest");
    let record = record.unwrap();
    assert_eq!(record.instance_id, instance_id);
    assert_eq!(record.processing_status, "Pending");

    // 1.5. Run instance_answers_monitor to process Pending request
    let input_txid = [1u8; 32];

    // Mock committee pubkey (valid secp256k1 pubkey)
    let committee_privkey =
        bitcoin::PrivateKey::from_slice(&[1u8; 32], bitcoin::Network::Regtest).unwrap();
    let committee_pubkey = committee_privkey.public_key(&bitcoin::secp256k1::Secp256k1::new());
    let committee_pubkey_bytes = committee_pubkey.to_bytes();
    let committee_addr = [4u8; 20];

    let pegin_data = PeginData {
        status: PeginStatus::Pending, // Must be Pending for answer
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats: 100000,
        txn_fees: [100, 100, 100],
        user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 200000 }],
        user_xonly_pubkey: [2u8; 32],
        user_change_addr: "bcrt1q...".to_string(),
        user_refund_addr: "bcrt1q...".to_string(),
        pegin_txid: [3u8; 32],
        created_at: 0,
        committee_addresses: vec![Address::from(committee_addr)],
        committee_pubkeys: vec![committee_pubkey_bytes],
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

    instance_answers_monitor(&local_db, &btc_client, &goat_client).await.unwrap();

    // Check status is now Processed
    let record = storage_processor
        .find_graph_goat_tx_record(&instance_id, &Uuid::nil(), tx_type)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.processing_status, "Processed");

    // 1.6 Simulate Processing Message (Creation of Instance)
    // Construct GenerateInstanceParams
    // We need to mock input tx in BTC client for generate_instance to work
    let bitcoin_txid = BitcoinTxid::from_byte_array(input_txid);

    // Use valid regtest address strings

    let user_change_address = bitcoin::Address::p2pkh(
        bitcoin::PublicKey::from_slice(&[2u8; 33]).unwrap(),
        bitcoin::Network::Regtest,
    );
    let user_refund_address = user_change_address.clone();

    let tx = Tx {
        txid: bitcoin_txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![Vout { scriptpubkey: user_change_address.script_pubkey(), value: 200000 }],
        fee: 100,
        size: 100,
        weight: 400,
        status: TxStatus {
            confirmed: true,
            block_height: Some(1),
            block_hash: None,
            block_time: None,
        },
    };

    // Mock adaptor for get_tx requires Tx (esplora) but we pass it.
    btc_mock.set_tx(bitcoin_txid, tx);

    let user_info = UserInfo {
        depositor_evm_address: [0u8; 20],
        txn_fees: [100, 100, 100],
        inputs: vec![Input {
            outpoint: OutPoint { txid: bitcoin_txid, vout: 0 },
            amount: Amount::from_sat(200000),
        }],
        user_xonly_pubkey: bitcoin::XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        user_change_address,
        user_refund_address,
    };

    let params = GenerateInstanceParams {
        instance_id,
        user_info,
        pegin_amount: Amount::from_sat(100000),
        pegin_request_tx_hash: "0x123".to_string(),
        pegin_request_height: 10,
        pegin_timestamp: 1600000000,
    };

    store_pegin_request(&btc_client, &local_db, params).await.unwrap();

    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::UserInited.to_string());

    // 2. Test UserInited -> CommitteesAnswered
    goat_mock.set_latest_block_number(20);

    // Run window monitor
    instance_window_expiration_monitor(&local_db, &goat_client).await.unwrap();

    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::CommitteesAnswered.to_string());

    // 3. Test CommitteesAnswered -> UserBroadcastPeginPrepare
    let btc_txid = instance.btc_txid.expect("btc_txid not set");

    // Mock BTC tx confirmed
    let txid = btc_txid.0;
    let tx = Tx {
        txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![],
        status: TxStatus {
            confirmed: true,
            block_height: Some(10),
            block_hash: None,
            block_time: None,
        },
        fee: 100,
        size: 100,
        weight: 400,
    };
    btc_mock.set_tx(txid, tx);

    instance_btc_tx_monitor(&local_db, &btc_client).await.unwrap();

    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::UserBroadcastPeginPrepare.to_string());

    // 4. Test -> Presigned (Simulated)
    let mut storage_processor = local_db.acquire().await.unwrap();
    storage_processor
        .update_instance(
            &InstanceUpdate::new_with_instance_id(instance_id)
                .with_status(InstanceBridgeInStatus::Presigned.to_string()),
        )
        .await
        .unwrap();

    // 5. Test Presigned -> RelayerL1Broadcasted
    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    let pegin_confirm_txid = instance.pegin_confirm_txid.expect("pegin_confirm not set");
    let txid = pegin_confirm_txid.0;

    let tx = Tx {
        txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![],
        status: TxStatus {
            confirmed: true,
            block_height: Some(15),
            block_hash: None,
            block_time: None,
        },
        fee: 100,
        size: 100,
        weight: 400,
    };
    btc_mock.set_tx(txid, tx);

    instance_btc_tx_monitor(&local_db, &btc_client).await.unwrap();

    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::RelayerL1Broadcasted.to_string());

    // 6. Test RelayerL1Broadcasted -> RelayerL2Minted
    let bridge_in_config = WatchEventConfig::Gateway(TheGraphConfig {
        address: Address::ZERO,
        the_graph_url: graph_url.clone(),
        event_entities: vec![BridgeIns],
    });

    event_watch_task::fetch_and_handle_block_range_events(
        actor.clone(),
        btc_client.clone(),
        goat_client.clone(),
        &client,
        &mut storage_processor,
        &bridge_in_config,
        0,
        100,
    )
    .await
    .unwrap();

    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::RelayerL2Minted.to_string());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_disprove_event() {
    let (local_db, btc_client, _, goat_client, _, _db_file) = setup().await;
    let actor = Actor::Challenger;
    let client = GraphQueryClient::new();

    // Wrap clients in Arc
    let btc_client = Arc::new(btc_client);
    let goat_client = Arc::new(goat_client);

    // Start a mock Graph Node server
    let graph_router = Router::new().route("/", post(mock_graph_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let graph_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, graph_router).await.unwrap();
    });

    let config = WatchEventConfig::Gateway(TheGraphConfig {
        address: Address::ZERO,
        the_graph_url: graph_url.clone(),
        event_entities: vec![GatewayEventEntity::WithdrawDisproveds],
    });

    let mut storage_processor = local_db.acquire().await.unwrap();

    // Seed Graph with status "Challenge"
    let graph_id = Uuid::from_str("11111111-1111-1111-1111-111111111111").unwrap();
    let instance_id = Uuid::new_v4();
    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::Challenge.to_string(),
        kickoff_index: 0,
        from_addr: "goat_addr".to_string(),
        to_addr: "btc_addr".to_string(),
        graph_ipfs_base_url: "".to_string(),
        amount: 1000,
        challenge_amount: 1000,
        sub_status: "{}".to_string(),
        operator_pubkey: "".to_string(),
        next_prekickoff: None,
        cur_prekickoff_txid: None,
        force_skip_kickoff_txid: None,
        quick_challenge_txid: None,
        challenge_incomplete_kickoff_txid: None,
        pegin_txid: None,
        kickoff_txid: None,
        take1_txid: None,
        challenge_txid: None,
        take2_txid: None,
        disprove_txid: None,
        watchtower_challenge_init_txid: None,
        watchtower_challenge_timeout_txids: vec![],
        nack_txids: vec![],
        blockhash_commit_timeout_txid: None,
        assert_init_txid: None,
        assert_commit_timeout_txids: vec![],
        init_withdraw_tx_hash: None,
        bridge_out_start_at: 0,
        zkm_version: "".to_string(),
        status_updated_at: 0,
        proceed_withdraw_height: 0,
        created_at: 0,
        updated_at: 0,
    };
    storage_processor.upsert_graph(&graph).await.unwrap();

    // Run event watch task
    event_watch_task::fetch_and_handle_block_range_events(
        actor,
        btc_client.clone(),
        goat_client.clone(),
        &client,
        &mut storage_processor,
        &config,
        0,
        100,
    )
    .await
    .unwrap();

    // Verify Graph Status Updated to Disprove
    let updated_graph = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated_graph.status, GraphStatus::Disprove.to_string());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_in_utxo_spent() {
    let (local_db, btc_client, btc_mock, goat_client, goat_mock, _db_file) = setup().await;

    // Create instance in UserInited state
    let instance_id = Uuid::new_v4();
    let input_txid = [2u8; 32];

    let bitcoin_txid = BitcoinTxid::from_byte_array(input_txid);
    let user_change_address = bitcoin::Address::p2pkh(
        bitcoin::PublicKey::from_slice(&[2u8; 33]).unwrap(),
        bitcoin::Network::Regtest,
    );
    let user_refund_address = user_change_address.clone();

    // Mock user input UTXO
    let user_info = UserInfo {
        depositor_evm_address: [0u8; 20],
        txn_fees: [100, 100, 100],
        inputs: vec![Input {
            outpoint: OutPoint { txid: bitcoin_txid, vout: 0 },
            amount: Amount::from_sat(200000),
        }],
        user_xonly_pubkey: bitcoin::XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        user_change_address: user_change_address.clone(),
        user_refund_address: user_refund_address.clone(),
    };

    let params = GenerateInstanceParams {
        instance_id,
        user_info,
        pegin_amount: Amount::from_sat(100000),
        pegin_request_tx_hash: "0x123".to_string(),
        pegin_request_height: 10,
        pegin_timestamp: 1600000000,
    };

    store_pegin_request(&btc_client, &local_db, params).await.unwrap();

    // Transition to CommitteesAnswered to generate btc_txid
    let committee_privkey =
        bitcoin::PrivateKey::from_slice(&[1u8; 32], bitcoin::Network::Regtest).unwrap();
    let committee_pubkey = committee_privkey.public_key(&bitcoin::secp256k1::Secp256k1::new());
    let committee_pubkey_bytes = committee_pubkey.to_bytes();
    let committee_addr = [4u8; 20];

    // Setup PeginData with committee info
    let pegin_data = PeginData {
        status: PeginStatus::Pending,
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats: 100000,
        txn_fees: [100, 100, 100],
        user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 200000 }],
        user_xonly_pubkey: [2u8; 32],
        user_change_addr: "bcrt1q...".to_string(),
        user_refund_addr: "bcrt1q...".to_string(),
        pegin_txid: [3u8; 32],
        created_at: 0,
        committee_addresses: vec![Address::from(committee_addr)],
        committee_pubkeys: vec![committee_pubkey_bytes],
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);
    goat_mock.set_latest_block_number(20);

    // Run window monitor to transition to CommitteesAnswered and generate btc_txid
    instance_window_expiration_monitor(&local_db, &goat_client).await.unwrap();

    let mut storage_processor = local_db.acquire().await.unwrap();
    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::CommitteesAnswered.to_string());
    assert!(instance.btc_txid.is_some());

    // Mock UTXO as spent by SOME OTHER txid
    let spending_txid = BitcoinTxid::from_byte_array([9u8; 32]);
    let input_txid_struct = BitcoinTxid::from_byte_array(input_txid);

    btc_mock.set_output_status(
        input_txid_struct,
        0,
        esplora_client::OutputStatus {
            spent: true,
            txid: Some(spending_txid),
            vin: Some(0),
            status: Some(TxStatus {
                confirmed: true,
                block_height: Some(100),
                block_hash: None,
                block_time: None,
            }),
        },
    );

    // Run btc monitor
    // logic:
    // - finds CommitteesAnswered instance
    // - btc_txid is present but not confirmed (mock doesn't say it is confirmed)
    // - checks if inputs of btc_txid are spent by someone else
    // - they ARE spent by spending_txid (diff from instance.btc_txid)
    // - status -> UserDiscarded
    instance_btc_tx_monitor(&local_db, &btc_client).await.unwrap();

    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeInStatus::UserDiscarded.to_string());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_refund() {
    let (local_db, btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup().await;
    let actor = Actor::Challenger;
    let client = GraphQueryClient::new();

    // Start Mock Graph
    let graph_router = Router::new().route("/", post(mock_graph_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let graph_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, graph_router).await.unwrap();
    });

    let btc_client = Arc::new(btc_client);
    let goat_client = Arc::new(goat_client);
    let swap_contract_addr =
        Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

    let config_init = WatchEventConfig::Swap(TheGraphConfig {
        address: swap_contract_addr,
        the_graph_url: graph_url.clone(),
        event_entities: vec![SwapEventEntity::Initializes],
    });

    let mut storage_processor = local_db.acquire().await.unwrap();

    // 1. Initialize Instance (Same as happy path)
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
    let escrow_hash = alloy::primitives::keccak256(escrow_data.abi_encode());

    let initialize_call = IEscrowManager::initializeCall {
        escrow: escrow_data.clone(),
        signature: Bytes::new(),
        timeout: U256::ZERO,
        _extraData: Bytes::new(),
    };
    let initialize_input = initialize_call.abi_encode();

    let initialize_tx_hash = "0xinit";
    let trace = GethTrace::CallTracer(CallFrame {
        from: Address::ZERO,
        gas: U256::ZERO,
        gas_used: U256::ZERO,
        to: Some(swap_contract_addr),
        input: initialize_input.into(),
        output: Some(Bytes::new()),
        error: None,
        revert_reason: None,
        calls: vec![],
        logs: vec![],
        value: Some(U256::ZERO),
        typ: "CALL".to_string(),
    });
    goat_mock.set_trace(initialize_tx_hash.to_string(), trace);

    event_watch_task::fetch_and_handle_block_range_events(
        actor.clone(),
        btc_client.clone(),
        goat_client.clone(),
        &client,
        &mut storage_processor,
        &config_init,
        0,
        100,
    )
    .await
    .unwrap();

    // Verify Initialized
    let (instances, _) = storage_processor
        .find_instances(
            InstanceQuery::default()
                .with_raw_condition(format!("escrow_hash = '0x{}'", hex::encode(escrow_hash.0))),
        )
        .await
        .unwrap();
    let instance = instances.first().expect("Instance not found");
    assert_eq!(instance.status, InstanceBridgeOutStatus::Initialize.to_string());

    // 2. Process Refund
    let config_refund = WatchEventConfig::Swap(TheGraphConfig {
        address: swap_contract_addr,
        the_graph_url: graph_url.clone(),
        event_entities: vec![SwapEventEntity::Refunds],
    });

    event_watch_task::fetch_and_handle_block_range_events(
        actor.clone(),
        btc_client.clone(),
        goat_client.clone(),
        &client,
        &mut storage_processor,
        &config_refund,
        101, // Simulate later block
        200,
    )
    .await
    .unwrap();

    let (instances, _) = storage_processor
        .find_instances(
            InstanceQuery::default()
                .with_raw_condition(format!("escrow_hash = '0x{}'", hex::encode(escrow_hash.0))),
        )
        .await
        .unwrap();
    let instance = instances.first().expect("Instance not found");
    assert_eq!(instance.status, InstanceBridgeOutStatus::Refund.to_string());
}

async fn mock_graph_handler(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let query = payload.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let mut data = serde_json::Map::new();

    use alloy::primitives::{Address, B256, U256, keccak256};
    use alloy::sol_types::SolValue;
    use bitvm2_noded::utils::evm_swap_utils::IEscrowManager::EscrowData;

    // Use test_fixtures for consistent IDs across tests and mock responses
    let instance_id_hex = test_fixtures::instance_id_hex();
    let graph_id_hex = test_fixtures::graph_id_hex();

    // Common EscrowData construction (same as in test)
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

    // Use regex word-boundary matching to prevent false matches (e.g., "claims" vs "reclaims")
    let matches_query = |pattern: &str| -> bool {
        Regex::new(&format!(r"\b{}\b", pattern)).map(|re| re.is_match(query)).unwrap_or(false)
    };

    if matches_query("initializes") {
        data.insert(
            "initializes".to_string(),
            serde_json::json!([
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
        );
    }

    if matches_query("claims") {
        data.insert(
            "claims".to_string(),
            serde_json::json!([
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
        );
    }

    if matches_query("refunds") {
        data.insert(
            "refunds".to_string(),
            serde_json::json!([
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
        );
    }

    if matches_query("bridgeInRequests") {
        data.insert("bridgeInRequests".to_string(), serde_json::json!([
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
            ]));
    }

    if matches_query("bridgeIns") {
        data.insert(
            "bridgeIns".to_string(),
            serde_json::json!([
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
        );
    }

    if matches_query("withdrawDisproveds") {
        data.insert(
            "withdrawDisproveds".to_string(),
            serde_json::json!([
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
        );
    }

    Json(serde_json::json!({
        "data": data
    }))
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_in_user_cancel() {
    let (local_db, btc_client, btc_mock, _, _, _db_file) = setup().await;

    // Create instance in Timeout state
    let instance_id = Uuid::new_v4();
    let pegin_cancel_txid = BitcoinTxid::from_byte_array([1u8; 32]);
    let instance = Instance {
        instance_id,
        is_bridge_in: true,
        network: "regtest".to_string(),
        status: InstanceBridgeInStatus::Timeout.to_string(),
        pegin_cancel_txid: Some(pegin_cancel_txid.into()),
        created_at: 0,
        ..Default::default()
    };

    let mut storage_processor = local_db.acquire().await.unwrap();
    storage_processor.upsert_instance(&instance).await.unwrap();

    // Mock confirmed refund tx
    btc_mock.set_tx(
        pegin_cancel_txid,
        Tx {
            txid: pegin_cancel_txid,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![],
            status: TxStatus {
                confirmed: true,
                block_height: Some(200),
                block_hash: None,
                block_time: None,
            },
            size: 100,
            weight: 400,
            fee: 1000,
        },
    );

    // Run monitor
    instance_btc_tx_monitor(&local_db, &btc_client).await.unwrap();

    // Check status
    let updated = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(updated.status, InstanceBridgeInStatus::UserCanceled.to_string());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_operator_kickoff() {
    let (local_db, _, _, _, _, _db_file) = setup().await;
    let mut storage_processor = local_db.acquire().await.unwrap();

    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();
    let init_withdraw_tx_hash = "0x123456".to_string();

    // Setup Graph
    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::OperatorPresigned.to_string(),
        init_withdraw_tx_hash: Some(init_withdraw_tx_hash.clone()),
        ..Default::default()
    };
    storage_processor.upsert_graph(&graph).await.unwrap();

    // Setup InitWithdraw Tx Record
    use bitvm2_noded::scheduled_tasks::graph_maintenance_tasks::detect_init_withdraw_call;
    use store::{GoatTxProcessingStatus, GoatTxRecord, GoatTxType};

    storage_processor
        .upsert_goat_tx_record(&GoatTxRecord {
            instance_id,
            graph_id,
            tx_type: GoatTxType::InitWithdraw.to_string(),
            tx_hash: init_withdraw_tx_hash,
            height: 100,
            is_local: false,
            processing_status: GoatTxProcessingStatus::Pending.to_string(),
            extra: None,
            created_at: 0,
        })
        .await
        .unwrap();

    // Run detector
    detect_init_withdraw_call(&local_db).await.unwrap();

    // Verify KickoffReady message
    let message = storage_processor
        .find_message_by_business_id(&graph_id, "KickoffReady")
        .await
        .unwrap()
        .unwrap();

    // Check message content
    // We can just check content contains "KickoffReady"
    let content_str = String::from_utf8(message.content).unwrap();
    assert!(content_str.contains("KickoffReady"));
    assert_eq!(message.state, store::MessageState::Pending.to_string());

    // Check tx record status updated
    let record = storage_processor
        .find_graph_goat_tx_record(&instance_id, &graph_id, &GoatTxType::InitWithdraw.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.processing_status, GoatTxProcessingStatus::Processed.to_string());
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_take2() {
    let (local_db, btc_client, btc_mock, _, _, _db_file) = setup().await;
    let mut storage_processor = local_db.acquire().await.unwrap();

    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    use bitvm2_noded::scheduled_tasks::graph_maintenance_tasks::{
        AssertCommitStatus, ChallengeSubStatus, CommitBlockHashStatus, WatchtowerChallengeStatus,
        process_graph_challenge,
    };
    use store::{GraphBtcTxVoutMonitor, SerializableTxid};

    // Create dummy TXIDs
    let kickoff_txid = SerializableTxid(BitcoinTxid::from_byte_array([1u8; 32]));
    let watchtower_init_txid = SerializableTxid(BitcoinTxid::from_byte_array([2u8; 32]));
    let assert_init_txid = SerializableTxid(BitcoinTxid::from_byte_array([3u8; 32]));
    let take2_txid = SerializableTxid(BitcoinTxid::from_byte_array([4u8; 32]));

    // Setup ChallengeSubStatus as Normal Finished
    let mut sub_status = ChallengeSubStatus::default();
    sub_status.watchtower_challenge_status =
        WatchtowerChallengeStatus::WatchtowerChallengeNormalFinished;
    sub_status.assert_commit_status = AssertCommitStatus::OperatorCommit;
    sub_status.commit_blockhash_status = CommitBlockHashStatus::OperatorCommit;

    let graph = Graph {
        graph_id,
        instance_id,
        operator_pubkey: "020000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        status: GraphStatus::Challenge.to_string(),
        sub_status: serde_json::to_string(&sub_status).unwrap(),
        kickoff_txid: Some(kickoff_txid.clone()),
        watchtower_challenge_init_txid: Some(watchtower_init_txid.clone()),
        assert_init_txid: Some(assert_init_txid.clone()),
        take2_txid: Some(take2_txid.clone()),
        ..Default::default()
    };
    storage_processor.upsert_graph(&graph).await.unwrap();

    // Create Monitors to provide heights
    storage_processor
        .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
            graph_id,
            tx_name: "watchtower_challenge_init".to_string(),
            txid: watchtower_init_txid.clone(),
            height: 100,
            vout_len: 2,
            monitor_data: "".to_string(),
            created_at: 0,
            updated_at: 0,
        })
        .await
        .unwrap();

    storage_processor
        .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
            graph_id,
            tx_name: "assert_init".to_string(),
            txid: assert_init_txid.clone(),
            height: 100,
            vout_len: 2,
            monitor_data: "".to_string(),
            created_at: 0,
            updated_at: 0,
        })
        .await
        .unwrap();

    // Set Mock Height
    btc_mock.set_height(100_000_000);

    // Set timelock env vars to ensure they are small
    unsafe {
        std::env::set_var("BITVM2_WATCHTOWER_CHALLENGE_INIT_OUT_TIMELOCK", "1");
        std::env::set_var("BITVM2_ASSERT_INIT_OUT_TIMELOCK", "1");
    }

    // Mock UTXO status for Kickoff, WatchtowerInit, AssertInit as Unspent
    use esplora_client::{OutputStatus, Tx, TxStatus};

    // Kickoff Vout 3 (Take2 input)
    btc_mock.set_output_status(
        kickoff_txid.0,
        3,
        OutputStatus { spent: false, txid: None, vin: None, status: None },
    );

    // Watchtower Init
    btc_mock.set_output_status(
        watchtower_init_txid.0,
        0,
        OutputStatus { spent: false, txid: None, vin: None, status: None },
    );
    // Add Tx Info in case DB lookup fails
    btc_mock.set_tx(
        watchtower_init_txid.0,
        Tx {
            txid: watchtower_init_txid.0,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![],
            status: TxStatus {
                confirmed: true,
                block_height: Some(100),
                block_hash: None,
                block_time: None,
            },
            size: 100,
            weight: 400,
            fee: 1000,
        },
    );

    // Assert Init
    btc_mock.set_output_status(
        assert_init_txid.0,
        0,
        OutputStatus { spent: false, txid: None, vin: None, status: None },
    );
    btc_mock.set_tx(
        assert_init_txid.0,
        Tx {
            txid: assert_init_txid.0,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![],
            status: TxStatus {
                confirmed: true,
                block_height: Some(100),
                block_hash: None,
                block_time: None,
            },
            size: 100,
            weight: 400,
            fee: 1000,
        },
    );

    // Run process_graph_challenge
    process_graph_challenge(&local_db, &btc_client).await.unwrap();

    // Verify Take2Ready message
    let message_opt =
        storage_processor.find_message_by_business_id(&graph_id, "Take2Ready").await.unwrap();

    let message = message_opt.unwrap();

    let content_str = String::from_utf8(message.content).unwrap();
    assert!(content_str.contains("Take2Ready"));
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_in_committee_fail() {
    let (local_db, _, _, goat_client, goat_mock, _db_file) = setup().await;
    let mut storage_processor = local_db.acquire().await.unwrap();

    let instance_id = Uuid::new_v4();

    use alloy::primitives::Address;
    use bitvm2_noded::scheduled_tasks::instance_maintenance_tasks::instance_window_expiration_monitor;
    use client::goat_chain::{PeginData, PeginStatus};
    use store::{Instance, InstanceBridgeInStatus, UInt64Array3};

    // Create Instance in UserInited state
    let instance = Instance {
        instance_id,
        is_bridge_in: true,
        status: InstanceBridgeInStatus::UserInited.to_string(),
        goat_tx_height: 100,
        input_utxos: "[]".to_string(),
        fees: UInt64Array3::default(),
        amount: 10000,
        ..Default::default()
    };
    storage_processor.upsert_instance(&instance).await.unwrap();

    // Set Mock State
    goat_mock.set_latest_block_number(200);
    goat_mock.set_quorum_size(3);

    // Mock Pegin Data with only 1 answer (Insufficient)
    let pegin_data = PeginData {
        status: PeginStatus::Pending,
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats: 10000,
        txn_fees: [0; 3],
        user_inputs: vec![],
        user_xonly_pubkey: [0u8; 32],
        user_change_addr: "".to_string(),
        user_refund_addr: "".to_string(),
        pegin_txid: [0u8; 32],
        created_at: 0,
        committee_addresses: vec![Address::ZERO],
        committee_pubkeys: vec![vec![1u8; 32]],
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

    // Run Monitor
    instance_window_expiration_monitor(&local_db, &goat_client).await.unwrap();

    // Verify Status
    let updated_instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(
        updated_instance.status,
        InstanceBridgeInStatus::NoEnoughCommitteesAnswered.to_string()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_complex_challenge() {
    let (local_db, btc_client, btc_mock, _, _, _db_file) = setup().await;
    let mut storage_processor = local_db.acquire().await.unwrap();

    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    use bitvm2_noded::scheduled_tasks::graph_maintenance_tasks::{
        ChallengeSubStatus, WTInitTxVoutMonitorData, WatchtowerChallengeItemStatus,
        process_graph_challenge,
    };
    use esplora_client::{OutputStatus, Tx, TxStatus};
    use store::{GraphBtcTxVoutMonitor, GraphStatus, SerializableTxid};

    // 1. Setup Graph
    let watchtower_init_txid = SerializableTxid(BitcoinTxid::from_byte_array([2u8; 32]));
    let blockhash_commit_timeout_txid = SerializableTxid(BitcoinTxid::from_byte_array([3u8; 32]));

    let graph = Graph {
        graph_id,
        instance_id,
        operator_pubkey: "020000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        status: GraphStatus::Challenge.to_string(),
        // sub_status default is None/Init, which is fine for triggering monitor logic
        sub_status: serde_json::to_string(&ChallengeSubStatus::default()).unwrap(),
        kickoff_txid: Some(SerializableTxid(BitcoinTxid::from_byte_array([1u8; 32]))),
        watchtower_challenge_init_txid: Some(watchtower_init_txid.clone()),
        blockhash_commit_timeout_txid: Some(blockhash_commit_timeout_txid.clone()),
        ..Default::default()
    };
    storage_processor.upsert_graph(&graph).await.unwrap();

    // 2. Setup Monitor Data
    // Index size 1. Index 0 is OperatorInit.
    let monitor_data_struct = WTInitTxVoutMonitorData::new(1);
    let monitor_data_json = serde_json::to_string(&monitor_data_struct).unwrap();

    let monitor = GraphBtcTxVoutMonitor {
        graph_id,
        tx_name: "watchtower_init".to_string(),
        txid: watchtower_init_txid.clone(),
        height: 100,
        vout_len: 2, // vout 0 and 1 for index 0
        monitor_data: monitor_data_json,
        created_at: 0,
        updated_at: 0,
    };
    storage_processor.upsert_graph_btc_tx_vout_monitor(&monitor).await.unwrap();

    // 3. Mock Watchtower Challenge (Spend vout 0 of watchtower_init_txid)
    let challenge_txid = BitcoinTxid::from_byte_array([9u8; 32]);
    btc_mock.set_output_status(
        watchtower_init_txid.0,
        0, // index 0 * 2 = 0
        OutputStatus {
            spent: true,
            txid: Some(challenge_txid),
            vin: Some(0),
            status: Some(TxStatus {
                confirmed: true,
                block_height: Some(200),
                block_hash: None,
                block_time: None,
            }),
        },
    );
    // Mock the challenge tx
    btc_mock.set_tx(
        challenge_txid,
        Tx {
            txid: challenge_txid,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![],
            status: TxStatus {
                confirmed: true,
                block_height: Some(200),
                block_hash: None,
                block_time: None,
            },
            size: 100,
            weight: 400,
            fee: 1000,
        },
    );

    // 4. Run Process
    process_graph_challenge(&local_db, &btc_client).await.unwrap();

    // 5. Verify Monitor Data Updated to "Challenge"
    let updated_monitor = storage_processor
        .find_graph_btc_tx_vout_monitor(&graph_id, &watchtower_init_txid)
        .await
        .unwrap()
        .unwrap();
    let updated_data: WTInitTxVoutMonitorData =
        serde_json::from_str(&updated_monitor.monitor_data).unwrap();

    assert_eq!(*updated_data.data_map.get(&0).unwrap(), WatchtowerChallengeItemStatus::Challenge);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_challenge_timeouts() {
    let (local_db, btc_client, btc_mock, _, _, _db_file) = setup().await;
    let mut storage_processor = local_db.acquire().await.unwrap();

    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();
    let operator_pubkey =
        "020000000000000000000000000000000000000000000000000000000000000001".to_string();

    use bitvm2_noded::scheduled_tasks::graph_maintenance_tasks::{
        ChallengeSubStatus, WTInitTxVoutMonitorData, WatchtowerChallengeItemStatus,
        WatchtowerChallengeStatus, process_graph_challenge,
    };
    use client::goat_chain::DisproveTxType;
    use store::{GraphBtcTxVoutMonitor, GraphStatus, SerializableTxid};

    // 1. Setup Graph with Challenge status
    let watchtower_init_txid = SerializableTxid(BitcoinTxid::from_byte_array([2u8; 32]));
    let blockhash_commit_timeout_txid = SerializableTxid(BitcoinTxid::from_byte_array([3u8; 32]));

    let graph = Graph {
        graph_id,
        instance_id,
        operator_pubkey,
        status: GraphStatus::Challenge.to_string(),
        sub_status: serde_json::to_string(&ChallengeSubStatus::default()).unwrap(),
        kickoff_txid: Some(SerializableTxid(BitcoinTxid::from_byte_array([1u8; 32]))),
        watchtower_challenge_init_txid: Some(watchtower_init_txid.clone()),
        blockhash_commit_timeout_txid: Some(blockhash_commit_timeout_txid.clone()),
        ..Default::default()
    };
    storage_processor.upsert_graph(&graph).await.unwrap();

    // 2. Setup Monitor Data with "Challenge" status (index 0)
    let mut monitor_data_struct = WTInitTxVoutMonitorData::new(1);
    monitor_data_struct.data_map.insert(0, WatchtowerChallengeItemStatus::Challenge);
    let monitor_data_json = serde_json::to_string(&monitor_data_struct).unwrap();

    let monitor = GraphBtcTxVoutMonitor {
        graph_id,
        tx_name: "watchtower_init".to_string(),
        txid: watchtower_init_txid.clone(),
        height: 100, // Created at height 100
        vout_len: 2,
        monitor_data: monitor_data_json,
        created_at: 0,
        updated_at: 0,
    };
    storage_processor.upsert_graph_btc_tx_vout_monitor(&monitor).await.unwrap();

    // 3. Set Height to Exceed Timeout (ACK Timeout)
    // Assume 100 + timelock < 100_000
    btc_mock.set_height(100_000);

    // 4. Run Process
    process_graph_challenge(&local_db, &btc_client).await.unwrap();

    // 5. Verify SubStatus Updated to OperatorNack
    let updated_graph = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
    let sub_status: ChallengeSubStatus = serde_json::from_str(&updated_graph.sub_status).unwrap();

    assert_eq!(
        sub_status.watchtower_challenge_status,
        WatchtowerChallengeStatus::WatchtowerChallengeDisproveFinished
    );
    assert_eq!(sub_status.disprove_type, Some(DisproveTxType::OperatorNack));
}
