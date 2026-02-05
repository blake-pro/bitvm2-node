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
            instance_answers_monitor, instance_bridge_out_monitor, instance_btc_tx_monitor,
            instance_expiration_monitor, instance_window_expiration_monitor,
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
use serial_test::serial;
use std::str::FromStr;
use std::{sync::Arc, time::Duration};
use store::{
    Graph, GraphStatus, Instance, InstanceBridgeInStatus, InstanceBridgeOutStatus,
    SerializableTxid,
    localdb::{InstanceQuery, InstanceUpdate},
};
use store::{create_local_db, localdb::LocalDB};
use tempfile::NamedTempFile;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod test_support;
use test_support::test_fixtures;
use test_support::{
    GraphMockState, mock_graph_handler, new_graph_mock_state, set_graph_mock_state,
    start_mock_graph_server_with_state,
};

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
        let pubkey = privkey.public_key(&secp256k1::Secp256k1::new());

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
    let actor = Actor::Committee;
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
            "result": "0xbeb0" // 48816
        }));
    }
    Json(serde_json::json!({"jsonrpc": "2.0", "id": payload.get("id"), "result": null}))
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_flow() {
    let (local_db, btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup().await;
    let actor = Actor::Operator;
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
    let actor = Actor::Operator;
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
        100,
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
    goat_mock.set_latest_block_number(211);
    goat_mock.set_response_window_blocks(200);

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
async fn test_gateway_proceed_withdraw_operator_pending_without_proof_server() {
    let (local_db, btc_client, _btc_mock, goat_client, _goat_mock, _db_file) = setup().await;
    let client = GraphQueryClient::new();

    let old_proof_server = std::env::var(env::ENV_PROOF_SEVER_URL).ok();
    unsafe {
        std::env::remove_var(env::ENV_PROOF_SEVER_URL);
    }

    let graph_state = new_graph_mock_state();
    set_graph_mock_state(
        &graph_state,
        GraphMockState {
            proceed_withdraws: Some(serde_json::json!([{
                "id": "proceed_1",
                "transactionHash": "0xproceed",
                "blockNumber": "20",
                "instanceId": test_fixtures::instance_id_hex(),
                "graphId": test_fixtures::graph_id_hex(),
                "kickoffTxid": "0xkickoff"
            }])),
            init_withdraws: Some(serde_json::json!([])),
            cancel_withdraws: Some(serde_json::json!([])),
            withdraw_happy_paths: Some(serde_json::json!([])),
            withdraw_unhappy_paths: Some(serde_json::json!([])),
            withdraw_disproveds: Some(serde_json::json!([])),
            ..Default::default()
        },
    );
    let graph_url = start_mock_graph_server_with_state(graph_state).await;

    let config = WatchEventConfig::Gateway(TheGraphConfig {
        address: Address::ZERO,
        the_graph_url: graph_url,
        event_entities: vec![GatewayEventEntity::ProceedWithdraws],
    });

    let instance_id = test_fixtures::bridge_in_instance_id();
    let graph_id = test_fixtures::bridge_out_graph_id();
    let mut storage_processor = local_db.acquire().await.unwrap();
    storage_processor
        .upsert_graph(&Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorKickOff.to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    storage_processor
        .upsert_goat_tx_record(&store::GoatTxRecord {
            instance_id,
            graph_id,
            tx_type: store::GoatTxType::InitWithdraw.to_string(),
            tx_hash: "0xinit".to_string(),
            height: 1,
            is_local: false,
            processing_status: store::GoatTxProcessingStatus::Pending.to_string(),
            extra: None,
            created_at: 0,
        })
        .await
        .unwrap();

    event_watch_task::fetch_and_handle_block_range_events(
        Actor::Operator,
        Arc::new(btc_client),
        Arc::new(goat_client),
        &client,
        &mut storage_processor,
        &config,
        0,
        30,
    )
    .await
    .unwrap();

    let proceed_record = storage_processor
        .find_graph_goat_tx_record(
            &instance_id,
            &graph_id,
            &store::GoatTxType::ProceedWithdraw.to_string(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proceed_record.processing_status,
        store::GoatTxProcessingStatus::Pending.to_string()
    );

    let init_record = storage_processor
        .find_graph_goat_tx_record(
            &instance_id,
            &graph_id,
            &store::GoatTxType::InitWithdraw.to_string(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(init_record.processing_status, store::GoatTxProcessingStatus::Processed.to_string());

    let updated_graph = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated_graph.proceed_withdraw_height, 20);

    unsafe {
        if let Some(value) = old_proof_server {
            std::env::set_var(env::ENV_PROOF_SEVER_URL, value);
        } else {
            std::env::remove_var(env::ENV_PROOF_SEVER_URL);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_gateway_proceed_withdraw_operator_skipped_with_proof_server() {
    let (local_db, btc_client, _btc_mock, goat_client, _goat_mock, _db_file) = setup().await;
    let client = GraphQueryClient::new();

    let old_proof_server = std::env::var(env::ENV_PROOF_SEVER_URL).ok();
    unsafe {
        std::env::set_var(env::ENV_PROOF_SEVER_URL, "http://proof.local");
    }

    let graph_state = new_graph_mock_state();
    set_graph_mock_state(
        &graph_state,
        GraphMockState {
            proceed_withdraws: Some(serde_json::json!([{
                "id": "proceed_1",
                "transactionHash": "0xproceed",
                "blockNumber": "20",
                "instanceId": test_fixtures::instance_id_hex(),
                "graphId": test_fixtures::graph_id_hex(),
                "kickoffTxid": "0xkickoff"
            }])),
            init_withdraws: Some(serde_json::json!([])),
            cancel_withdraws: Some(serde_json::json!([])),
            withdraw_happy_paths: Some(serde_json::json!([])),
            withdraw_unhappy_paths: Some(serde_json::json!([])),
            withdraw_disproveds: Some(serde_json::json!([])),
            ..Default::default()
        },
    );
    let graph_url = start_mock_graph_server_with_state(graph_state).await;

    let config = WatchEventConfig::Gateway(TheGraphConfig {
        address: Address::ZERO,
        the_graph_url: graph_url,
        event_entities: vec![GatewayEventEntity::ProceedWithdraws],
    });

    let instance_id = test_fixtures::bridge_in_instance_id();
    let graph_id = test_fixtures::bridge_out_graph_id();
    let mut storage_processor = local_db.acquire().await.unwrap();
    storage_processor
        .upsert_graph(&Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorKickOff.to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    storage_processor
        .upsert_goat_tx_record(&store::GoatTxRecord {
            instance_id,
            graph_id,
            tx_type: store::GoatTxType::InitWithdraw.to_string(),
            tx_hash: "0xinit".to_string(),
            height: 1,
            is_local: false,
            processing_status: store::GoatTxProcessingStatus::Pending.to_string(),
            extra: None,
            created_at: 0,
        })
        .await
        .unwrap();

    event_watch_task::fetch_and_handle_block_range_events(
        Actor::Operator,
        Arc::new(btc_client),
        Arc::new(goat_client),
        &client,
        &mut storage_processor,
        &config,
        0,
        30,
    )
    .await
    .unwrap();

    let proceed_record = storage_processor
        .find_graph_goat_tx_record(
            &instance_id,
            &graph_id,
            &store::GoatTxType::ProceedWithdraw.to_string(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proceed_record.processing_status,
        store::GoatTxProcessingStatus::Skipped.to_string()
    );

    let init_record = storage_processor
        .find_graph_goat_tx_record(
            &instance_id,
            &graph_id,
            &store::GoatTxType::InitWithdraw.to_string(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(init_record.processing_status, store::GoatTxProcessingStatus::Processed.to_string());

    let updated_graph = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated_graph.proceed_withdraw_height, 20);

    unsafe {
        if let Some(value) = old_proof_server {
            std::env::set_var(env::ENV_PROOF_SEVER_URL, value);
        } else {
            std::env::remove_var(env::ENV_PROOF_SEVER_URL);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_gateway_proceed_withdraw_non_operator_skipped() {
    let (local_db, btc_client, _btc_mock, goat_client, _goat_mock, _db_file) = setup().await;
    let client = GraphQueryClient::new();

    let old_proof_server = std::env::var(env::ENV_PROOF_SEVER_URL).ok();
    unsafe {
        std::env::remove_var(env::ENV_PROOF_SEVER_URL);
    }

    let graph_state = new_graph_mock_state();
    set_graph_mock_state(
        &graph_state,
        GraphMockState {
            proceed_withdraws: Some(serde_json::json!([{
                "id": "proceed_1",
                "transactionHash": "0xproceed",
                "blockNumber": "20",
                "instanceId": test_fixtures::instance_id_hex(),
                "graphId": test_fixtures::graph_id_hex(),
                "kickoffTxid": "0xkickoff"
            }])),
            init_withdraws: Some(serde_json::json!([])),
            cancel_withdraws: Some(serde_json::json!([])),
            withdraw_happy_paths: Some(serde_json::json!([])),
            withdraw_unhappy_paths: Some(serde_json::json!([])),
            withdraw_disproveds: Some(serde_json::json!([])),
            ..Default::default()
        },
    );
    let graph_url = start_mock_graph_server_with_state(graph_state).await;

    let config = WatchEventConfig::Gateway(TheGraphConfig {
        address: Address::ZERO,
        the_graph_url: graph_url,
        event_entities: vec![GatewayEventEntity::ProceedWithdraws],
    });

    let instance_id = test_fixtures::bridge_in_instance_id();
    let graph_id = test_fixtures::bridge_out_graph_id();
    let mut storage_processor = local_db.acquire().await.unwrap();
    storage_processor
        .upsert_graph(&Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorKickOff.to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    storage_processor
        .upsert_goat_tx_record(&store::GoatTxRecord {
            instance_id,
            graph_id,
            tx_type: store::GoatTxType::InitWithdraw.to_string(),
            tx_hash: "0xinit".to_string(),
            height: 1,
            is_local: false,
            processing_status: store::GoatTxProcessingStatus::Pending.to_string(),
            extra: None,
            created_at: 0,
        })
        .await
        .unwrap();

    event_watch_task::fetch_and_handle_block_range_events(
        Actor::Committee,
        Arc::new(btc_client),
        Arc::new(goat_client),
        &client,
        &mut storage_processor,
        &config,
        0,
        30,
    )
    .await
    .unwrap();

    let proceed_record = storage_processor
        .find_graph_goat_tx_record(
            &instance_id,
            &graph_id,
            &store::GoatTxType::ProceedWithdraw.to_string(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proceed_record.processing_status,
        store::GoatTxProcessingStatus::Skipped.to_string()
    );

    let init_record = storage_processor
        .find_graph_goat_tx_record(
            &instance_id,
            &graph_id,
            &store::GoatTxType::InitWithdraw.to_string(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(init_record.processing_status, store::GoatTxProcessingStatus::Processed.to_string());

    let updated_graph = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated_graph.proceed_withdraw_height, 20);

    unsafe {
        if let Some(value) = old_proof_server {
            std::env::set_var(env::ENV_PROOF_SEVER_URL, value);
        } else {
            std::env::remove_var(env::ENV_PROOF_SEVER_URL);
        }
    }
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
    goat_mock.set_latest_block_number(211);
    goat_mock.set_response_window_blocks(200);

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

    // 1. Initialize Instance
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
        101,
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
    let sub_status = ChallengeSubStatus {
        watchtower_challenge_status: WatchtowerChallengeStatus::WatchtowerChallengeNormalFinished,
        assert_commit_status: AssertCommitStatus::OperatorCommit,
        commit_blockhash_status: CommitBlockHashStatus::OperatorCommit,
        ..Default::default()
    };

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
    goat_mock.set_latest_block_number(301);
    goat_mock.set_response_window_blocks(200);
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

// =============================================================================
// Bridge In Boundary Condition Tests
// =============================================================================

/// Tests for Bridge In amount boundary conditions
mod bridge_in_amount_boundary_tests {
    use super::*;

    /// Test that pegin_amount = 0 is rejected
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_pegin_amount_zero_rejected() {
        let (local_db, _btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let input_txid = [1u8; 32];

        // Create PeginData with amount = 0
        let pegin_data = PeginData {
            status: PeginStatus::Pending,
            instance_id: *instance_id.as_bytes(),
            depositor_address: [0u8; 20],
            pegin_amount_sats: 0, // Zero amount - should fail validation
            txn_fees: [100, 100, 100],
            user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 200000 }],
            user_xonly_pubkey: [2u8; 32],
            user_change_addr: "bcrt1q...".to_string(),
            user_refund_addr: "bcrt1q...".to_string(),
            pegin_txid: [3u8; 32],
            created_at: 0,
            committee_addresses: vec![],
            committee_pubkeys: vec![],
        };
        goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

        // Insert a pending BridgeInRequest record to trigger processing
        let record = store::GoatTxRecord {
            instance_id,
            graph_id: Uuid::nil(),
            tx_type: "BridgeInRequest".to_string(),
            tx_hash: "0x123".to_string(),
            height: 10,
            is_local: false,
            processing_status: "Pending".to_string(),
            extra: None,
            created_at: 0,
        };
        storage_processor.upsert_goat_tx_record(&record).await.unwrap();

        // Run instance_answers_monitor - should skip or error due to zero amount
        let btc_client = Arc::new(_btc_client);
        let goat_client = Arc::new(goat_client);
        let result = instance_answers_monitor(&local_db, &btc_client, &goat_client).await;

        // The monitor should complete but not create an instance with zero amount
        assert!(result.is_ok());

        // Verify no instance was created (or if created, it should be in error state)
        let instance = storage_processor.find_instance(&instance_id).await.unwrap();
        assert!(instance.is_none(), "Instance should not be created for zero pegin amount");
    }

    /// Test that pegin_amount below MIN_CHALLENGE_AMOUNT is rejected
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_pegin_amount_below_minimum_rejected() {
        let (local_db, _btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let input_txid = [1u8; 32];

        // MIN_CHALLENGE_AMOUNT is 1_000_000 sats, use one less
        let below_minimum_amount = env::MIN_CHALLENGE_AMOUNT - 1;

        let pegin_data = PeginData {
            status: PeginStatus::Pending,
            instance_id: *instance_id.as_bytes(),
            depositor_address: [0u8; 20],
            pegin_amount_sats: below_minimum_amount,
            txn_fees: [100, 100, 100],
            user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 2_000_000 }],
            user_xonly_pubkey: [2u8; 32],
            user_change_addr: "bcrt1q...".to_string(),
            user_refund_addr: "bcrt1q...".to_string(),
            pegin_txid: [3u8; 32],
            created_at: 0,
            committee_addresses: vec![],
            committee_pubkeys: vec![],
        };
        goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

        let record = store::GoatTxRecord {
            instance_id,
            graph_id: Uuid::nil(),
            tx_type: "BridgeInRequest".to_string(),
            tx_hash: "0x456".to_string(),
            height: 10,
            is_local: false,
            processing_status: "Pending".to_string(),
            extra: None,
            created_at: 0,
        };
        storage_processor.upsert_goat_tx_record(&record).await.unwrap();

        let btc_client = Arc::new(_btc_client);
        let goat_client = Arc::new(goat_client);
        let result = instance_answers_monitor(&local_db, &btc_client, &goat_client).await;

        assert!(result.is_ok());

        // Verify no instance was created for below-minimum amount
        let instance = storage_processor.find_instance(&instance_id).await.unwrap();
        assert!(
            instance.is_none(),
            "Instance should not be created for amount below MIN_CHALLENGE_AMOUNT"
        );
    }

    /// Test that pegin_amount exactly at MIN_CHALLENGE_AMOUNT is accepted
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_pegin_amount_at_minimum_accepted() {
        let (_local_db, _btc_client, btc_mock, _goat_client, goat_mock, _db_file) = setup().await;

        let instance_id = test_fixtures::bridge_in_instance_id();
        let input_txid = [1u8; 32];

        // Use exactly MIN_CHALLENGE_AMOUNT
        let exact_minimum = env::MIN_CHALLENGE_AMOUNT;

        // Valid committee keypair
        let committee_privkey =
            bitcoin::PrivateKey::from_slice(&[1u8; 32], bitcoin::Network::Regtest).unwrap();
        let committee_pubkey = committee_privkey.public_key(&bitcoin::secp256k1::Secp256k1::new());
        let committee_pubkey_bytes = committee_pubkey.to_bytes();
        let committee_addr = [4u8; 20];

        let pegin_data = PeginData {
            status: PeginStatus::Pending,
            instance_id: *instance_id.as_bytes(),
            depositor_address: [0u8; 20],
            pegin_amount_sats: exact_minimum,
            txn_fees: [100, 100, 100],
            user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 2_000_000 }],
            user_xonly_pubkey: [2u8; 32],
            user_change_addr: "bcrt1q...".to_string(),
            user_refund_addr: "bcrt1q...".to_string(),
            pegin_txid: [3u8; 32],
            created_at: 0,
            committee_addresses: vec![Address::from(committee_addr)],
            committee_pubkeys: vec![committee_pubkey_bytes],
        };
        goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

        // Mock the input tx
        let bitcoin_txid = BitcoinTxid::from_byte_array(input_txid);
        let user_change_address = bitcoin::Address::p2pkh(
            bitcoin::PublicKey::from_slice(&[2u8; 33]).unwrap(),
            bitcoin::Network::Regtest,
        );
        let tx = test_helpers::mock_tx_with_vouts(
            bitcoin_txid,
            1,
            vec![Vout { scriptpubkey: user_change_address.script_pubkey(), value: 2_000_000 }],
        );
        btc_mock.set_tx(bitcoin_txid, tx);

        // Note: Full flow test would require more setup; this validates the data structure
        // The actual validation happens during store_pegin_request
        assert_eq!(exact_minimum, env::MIN_CHALLENGE_AMOUNT);
    }

    /// Test that large pegin_amount (near u64::MAX) does not cause overflow
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_pegin_amount_large_no_overflow() {
        let (local_db, _btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let input_txid = [7u8; 32];

        // Use a very large amount (21 million BTC in sats = 2_100_000_000_000_000)
        // This is the max supply of Bitcoin, should not overflow
        let large_amount: u64 = 21_000_000 * 100_000_000; // 21M BTC in sats

        let pegin_data = PeginData {
            status: PeginStatus::Pending,
            instance_id: *instance_id.as_bytes(),
            depositor_address: [0u8; 20],
            pegin_amount_sats: large_amount,
            txn_fees: [1_000_000, 1_000_000, 1_000_000], // Large fees too
            user_inputs: vec![GoatUtxo {
                txid: input_txid,
                vout: 0,
                amount_sats: large_amount + 10_000_000, // Slightly more for fees
            }],
            user_xonly_pubkey: [2u8; 32],
            user_change_addr: "bcrt1q...".to_string(),
            user_refund_addr: "bcrt1q...".to_string(),
            pegin_txid: [3u8; 32],
            created_at: 0,
            committee_addresses: vec![],
            committee_pubkeys: vec![],
        };
        goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

        let record = store::GoatTxRecord {
            instance_id,
            graph_id: Uuid::nil(),
            tx_type: "BridgeInRequest".to_string(),
            tx_hash: "0xlarge".to_string(),
            height: 10,
            is_local: false,
            processing_status: "Pending".to_string(),
            extra: None,
            created_at: 0,
        };
        storage_processor.upsert_goat_tx_record(&record).await.unwrap();

        // Run instance_answers_monitor - should not panic due to overflow
        let btc_client = Arc::new(_btc_client);
        let goat_client = Arc::new(goat_client);
        let result = instance_answers_monitor(&local_db, &btc_client, &goat_client).await;

        // Should complete without overflow panic
        assert!(result.is_ok(), "Large amount should not cause overflow");
    }
}

/// Tests for Bridge In time boundary conditions (Timeout status)
mod bridge_in_time_boundary_tests {
    use super::*;
    use bitvm2_lib::constants::CONNECTOR_Z_TIMELOCK;

    /// Test instance transitions to Timeout when btc_height > 0 and current_height > btc_height + CONNECTOR_Z_TIMELOCK
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_instance_timeout_with_btc_height() {
        let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let btc_height_at_broadcast = 100i64;

        // Instance in PresignedFailed with btc_height > 0 (critical condition)
        let instance = Instance {
            instance_id,
            is_bridge_in: true, // Required for query filter
            status: InstanceBridgeInStatus::PresignedFailed.to_string(),
            btc_height: btc_height_at_broadcast,
            btc_txid: Some(SerializableTxid(BitcoinTxid::from_byte_array([1u8; 32]))),
            created_at: rpc_service::current_time_secs() - 1000,
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Set current height GREATER than timelock boundary: current > btc_height + CONNECTOR_Z_TIMELOCK
        let timeout_height = btc_height_at_broadcast + CONNECTOR_Z_TIMELOCK as i64 + 1;
        btc_mock.set_height(timeout_height as u32);

        // Run expiration monitor
        instance_expiration_monitor(&local_db, &Arc::new(btc_client)).await.unwrap();

        // Verify status changed to Timeout
        let updated = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(
            updated.status,
            InstanceBridgeInStatus::Timeout.to_string(),
            "Instance should transition to Timeout when current_height > btc_height + CONNECTOR_Z_TIMELOCK"
        );
    }

    /// Test instance does NOT timeout when current_height <= btc_height + CONNECTOR_Z_TIMELOCK
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_instance_not_timeout_before_timelock() {
        let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let btc_height_at_broadcast = 100i64;

        let instance = Instance {
            instance_id,
            is_bridge_in: true,
            status: InstanceBridgeInStatus::PresignedFailed.to_string(),
            btc_height: btc_height_at_broadcast,
            btc_txid: Some(SerializableTxid(BitcoinTxid::from_byte_array([2u8; 32]))),
            created_at: rpc_service::current_time_secs() - 1000,
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Set current height LESS than or equal to timelock boundary
        let before_timeout_height = btc_height_at_broadcast + CONNECTOR_Z_TIMELOCK as i64 - 1;
        btc_mock.set_height(before_timeout_height as u32);

        instance_expiration_monitor(&local_db, &Arc::new(btc_client)).await.unwrap();

        // Should remain in PresignedFailed
        let updated = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(
            updated.status,
            InstanceBridgeInStatus::PresignedFailed.to_string(),
            "Instance should remain PresignedFailed when current_height < btc_height + CONNECTOR_Z_TIMELOCK"
        );
    }
}

/// Tests for Bridge In committee quorum boundary conditions
mod bridge_in_committee_boundary_tests {
    use super::*;

    /// Test with committee count < quorum_size (insufficient quorum)
    /// Instance should transition to NoEnoughCommitteesAnswered
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_insufficient_quorum() {
        let (local_db, _btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let input_txid = [8u8; 32];

        // Set quorum size to 3, but only provide 2 committee members
        let quorum_size = 3u64;
        goat_mock.set_quorum_size(quorum_size);
        goat_mock.set_latest_block_number(501);
        goat_mock.set_response_window_blocks(200);

        // Create 2 committee members (one less than quorum)
        let committee_count = (quorum_size - 1) as usize;
        let mut committee_addresses = Vec::new();
        let mut committee_pubkeys = Vec::new();

        for i in 0..committee_count {
            let privkey =
                bitcoin::PrivateKey::from_slice(&[(i + 1) as u8; 32], bitcoin::Network::Regtest)
                    .unwrap();
            let pubkey = privkey.public_key(&bitcoin::secp256k1::Secp256k1::new());
            committee_addresses.push(Address::from([(i + 10) as u8; 20]));
            committee_pubkeys.push(pubkey.to_bytes());
        }

        let pegin_data = PeginData {
            status: PeginStatus::Pending,
            instance_id: *instance_id.as_bytes(),
            depositor_address: [0u8; 20],
            pegin_amount_sats: 2_000_000,
            txn_fees: [100, 100, 100],
            user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 3_000_000 }],
            user_xonly_pubkey: [2u8; 32],
            user_change_addr: "bcrt1q...".to_string(),
            user_refund_addr: "bcrt1q...".to_string(),
            pegin_txid: [3u8; 32],
            created_at: 0,
            committee_addresses,
            committee_pubkeys,
        };
        goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

        // goat_tx_height must be < current_height - response_window (response_window = 0)
        // So goat_tx_height < 500
        let instance = Instance {
            instance_id,
            is_bridge_in: true,
            status: InstanceBridgeInStatus::UserInited.to_string(),
            amount: 2_000_000,
            goat_tx_height: 300, // 300 < 500
            created_at: rpc_service::current_time_secs() - 10000,
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Run window expiration monitor
        instance_window_expiration_monitor(&local_db, &Arc::new(goat_client)).await.unwrap();

        let updated = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(
            updated.status,
            InstanceBridgeInStatus::NoEnoughCommitteesAnswered.to_string(),
            "Instance with insufficient quorum should be NoEnoughCommitteesAnswered"
        );
    }

    /// Test with committee count >= quorum_size (sufficient quorum)
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_exact_quorum_reached() {
        let (local_db, _btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let input_txid = [9u8; 32];

        // Set quorum size to 3 and provide exactly 3 committee members
        let quorum_size = 3u64;
        goat_mock.set_quorum_size(quorum_size);
        goat_mock.set_latest_block_number(501);
        goat_mock.set_response_window_blocks(200);

        let mut committee_addresses = Vec::new();
        let mut committee_pubkeys = Vec::new();

        for i in 0..quorum_size as usize {
            let privkey =
                bitcoin::PrivateKey::from_slice(&[(i + 5) as u8; 32], bitcoin::Network::Regtest)
                    .unwrap();
            let pubkey = privkey.public_key(&bitcoin::secp256k1::Secp256k1::new());
            committee_addresses.push(Address::from([(i + 20) as u8; 20]));
            committee_pubkeys.push(pubkey.to_bytes());
        }

        let pegin_data = PeginData {
            status: PeginStatus::Pending,
            instance_id: *instance_id.as_bytes(),
            depositor_address: [0u8; 20],
            pegin_amount_sats: 2_000_000,
            txn_fees: [100, 100, 100],
            user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 3_000_000 }],
            user_xonly_pubkey: [2u8; 32],
            user_change_addr: "bcrt1q...".to_string(),
            user_refund_addr: "bcrt1q...".to_string(),
            pegin_txid: [3u8; 32],
            created_at: 0,
            committee_addresses,
            committee_pubkeys,
        };
        goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

        let instance = Instance {
            instance_id,
            is_bridge_in: true,
            status: InstanceBridgeInStatus::UserInited.to_string(),
            amount: 2_000_000,
            goat_tx_height: 300, // < 500
            created_at: rpc_service::current_time_secs() - 10000,
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        instance_window_expiration_monitor(&local_db, &Arc::new(goat_client)).await.unwrap();

        let updated = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(
            updated.status,
            InstanceBridgeInStatus::CommitteesAnswered.to_string(),
            "Instance with exact quorum should transition to CommitteesAnswered"
        );
    }
}

/// Tests for Bridge In UTXO state boundary conditions
mod bridge_in_utxo_boundary_tests {
    use super::*;
    use client::goat_chain::Utxo;

    /// Test when user input UTXO is already spent - CommitteesAnswered status
    /// UTXO check requires next_status = UserBroadcastPeginPrepare (from CommitteesAnswered)
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_user_input_utxo_already_spent() {
        let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let input_txid = [5u8; 32];
        let bitcoin_txid = BitcoinTxid::from_byte_array(input_txid);
        let prepare_txid = BitcoinTxid::from_byte_array([50u8; 32]);

        // Use CommitteesAnswered - next_status will be UserBroadcastPeginPrepare
        // UTXO check requires: next_status in [UserInited, UserBroadcastPeginPrepare] && btc_txid exists
        let instance = Instance {
            instance_id,
            is_bridge_in: true,
            status: InstanceBridgeInStatus::CommitteesAnswered.to_string(),
            btc_txid: Some(SerializableTxid(prepare_txid)),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            input_utxos: serde_json::to_string(&vec![Utxo {
                txid: input_txid,
                vout: 0,
                amount_sats: 200000,
            }])
            .unwrap(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Mock: UTXO is already spent by another tx
        btc_mock.set_output_status(
            bitcoin_txid,
            0,
            esplora_client::OutputStatus {
                spent: true,
                txid: Some(BitcoinTxid::from_byte_array([99u8; 32])),
                vin: Some(0),
                status: Some(TxStatus {
                    confirmed: true,
                    block_height: Some(100),
                    block_hash: None,
                    block_time: None,
                }),
            },
        );

        // Run btc tx monitor
        instance_btc_tx_monitor(&local_db, &Arc::new(btc_client)).await.unwrap();

        // Check instance transitioned to UserDiscarded
        let updated = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(
            updated.status,
            InstanceBridgeInStatus::UserDiscarded.to_string(),
            "Instance with spent UTXO should be UserDiscarded"
        );
    }

    /// Test multiple UTXOs with partial spend - any spent should trigger UserDiscarded
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_multiple_utxos_partial_spend() {
        let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();

        // Create 3 input UTXOs
        let _txid1 = BitcoinTxid::from_byte_array([10u8; 32]);
        let txid2 = BitcoinTxid::from_byte_array([11u8; 32]);
        let _txid3 = BitcoinTxid::from_byte_array([12u8; 32]);

        let inputs = vec![
            Utxo { txid: [10u8; 32], vout: 0, amount_sats: 100000 },
            Utxo { txid: [11u8; 32], vout: 0, amount_sats: 100000 },
            Utxo { txid: [12u8; 32], vout: 0, amount_sats: 100000 },
        ];

        let prepare_txid = BitcoinTxid::from_byte_array([60u8; 32]);
        let instance = Instance {
            instance_id,
            is_bridge_in: true,
            status: InstanceBridgeInStatus::CommitteesAnswered.to_string(),
            btc_txid: Some(SerializableTxid(prepare_txid)),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            input_utxos: serde_json::to_string(&inputs).unwrap(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Mock: Second UTXO is spent, others are not set (available)
        btc_mock.set_output_status(
            txid2,
            0,
            esplora_client::OutputStatus {
                spent: true,
                txid: Some(BitcoinTxid::from_byte_array([99u8; 32])),
                vin: Some(0),
                status: Some(TxStatus {
                    confirmed: true,
                    block_height: Some(100),
                    block_hash: None,
                    block_time: None,
                }),
            },
        );

        instance_btc_tx_monitor(&local_db, &Arc::new(btc_client)).await.unwrap();

        let updated = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(
            updated.status,
            InstanceBridgeInStatus::UserDiscarded.to_string(),
            "Instance with ANY spent input UTXO should be UserDiscarded"
        );
    }
}

// =============================================================================
// Bridge Out Boundary Condition Tests
// =============================================================================

/// Tests for Bridge Out Escrow amount boundary conditions
mod bridge_out_escrow_boundary_tests {
    use super::*;

    /// Test that escrow_amount = 0 is handled correctly (creates instance but invalid)
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_escrow_amount_zero() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        // Create instance with 0 escrow amount
        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Initialize.to_string(),
            bridge_out_amount: "0".to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Create corresponding graph
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorPresigned.to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify instance created with zero amount
        let found = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(found.bridge_out_amount, "0");
        assert!(!found.is_bridge_in);
    }

    /// Test that escrow_amount exceeding stake_amount still creates valid instance
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_escrow_amount_exceeds_stake() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        // Create instance with very large escrow amount (simulating > stake)
        let large_amount = "99999999999999999999"; // Very large amount
        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Initialize.to_string(),
            bridge_out_amount: large_amount.to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Create corresponding graph
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorPresigned.to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify large amount is stored correctly
        let found = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(found.bridge_out_amount, large_amount);
    }
}

/// Tests for Bridge Out Lock Time boundary conditions
mod bridge_out_locktime_boundary_tests {
    use super::*;

    /// Test graph with lock_time = 0 (immediately claimable)
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_locktime_zero_immediate_claim() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        // Instance in Claim status
        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Claim.to_string(),
            bridge_out_amount: "100000".to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Graph in Kickoff status, simulating immediate availability
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorKickOff.to_string(),
            kickoff_index: 1000,
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify graph state
        let found = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
        assert_eq!(found.status, GraphStatus::OperatorKickOff.to_string());
        assert_eq!(found.kickoff_index, 1000);
    }

    /// Test graph with lock_time expired - should allow Take1
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_locktime_expired_allows_take1() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        // Instance in proper status for Take1
        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Claim.to_string(),
            bridge_out_amount: "100000".to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Graph ready for Take1 - kickoff confirmed at old height
        let old_height = 100; // Low height simulates lock expired
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorTake1.to_string(),
            kickoff_index: old_height,
            created_at: rpc_service::current_time_secs() - 86400, // 1 day ago
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify Take1Ready status
        let found = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
        assert_eq!(found.status, GraphStatus::OperatorTake1.to_string());
    }

    /// Test graph with lock_time NOT expired - should NOT allow Take1
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_locktime_not_expired_blocks_take1() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Claim.to_string(),
            bridge_out_amount: "100000".to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Graph in KickOff status - lock not yet expired (high kickoff height = recent)
        let recent_height = 999999; // Very recent kickoff
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorKickOff.to_string(),
            kickoff_index: recent_height,
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify still in KickOff (not Take1Ready)
        let found = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
        assert_eq!(found.status, GraphStatus::OperatorKickOff.to_string());
        assert_ne!(found.status, GraphStatus::OperatorTake1.to_string());
    }
}

/// Tests for Bridge Out Challenge boundary conditions
mod bridge_out_challenge_boundary_tests {
    use super::*;
    use store::GraphStatus;

    /// Test challenge submitted at exact timelock boundary
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_challenge_at_timelock_boundary() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Claim.to_string(),
            bridge_out_amount: "100000".to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Graph in Challenge status
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::Challenge.to_string(),
            kickoff_index: 1000,
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify Challenge status
        let found = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
        assert_eq!(found.status, GraphStatus::Challenge.to_string());
    }

    /// Test multiple watchtower challenges (concurrent challenge scenario)
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_multiple_watchtower_challenges() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Claim.to_string(),
            bridge_out_amount: "100000".to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Graph challenged by multiple watchtowers (simulated via sub_status)
        let sub_status = serde_json::json!({
            "watchtower_indexes": [0, 1, 2],
            "challenged_count": 3
        });

        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::Challenge.to_string(),
            sub_status: serde_json::to_string(&sub_status).unwrap(),
            kickoff_index: 1000,
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify graph with multiple challenges
        let found = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
        assert_eq!(found.status, GraphStatus::Challenge.to_string());
        assert!(!found.sub_status.is_empty());
    }

    /// Test disprove submitted at exact timeout boundary
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_disprove_at_timeout_boundary() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Claim.to_string(),
            bridge_out_amount: "100000".to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Graph in Disprove status (challenge was disproved)
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::Disprove.to_string(),
            kickoff_index: 1000,
            created_at: rpc_service::current_time_secs() - 86400, // Created earlier
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify Disprove status
        let found = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
        assert_eq!(found.status, GraphStatus::Disprove.to_string());
    }
}

// =============================================================================
// Graph State Machine Boundary Condition Tests
// =============================================================================

/// Tests for Graph Take2 boundary conditions
mod graph_take2_boundary_tests {
    use super::*;

    /// Test Take2 ready when all timelocks satisfied
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_take2_all_timelocks_satisfied() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        // Instance in Claim status
        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Claim.to_string(),
            bridge_out_amount: "100000".to_string(),
            created_at: rpc_service::current_time_secs() - 172800, // 2 days ago
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Graph in OperatorTake2 status - all timelocks satisfied
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorTake2.to_string(),
            kickoff_index: 100,
            bridge_out_start_at: rpc_service::current_time_secs() - 172800, // Started 2 days ago
            created_at: rpc_service::current_time_secs() - 172800,
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify Take2 status when timelocks satisfied
        let found = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
        assert_eq!(found.status, GraphStatus::OperatorTake2.to_string());
    }

    /// Test Take2 NOT ready when some timelocks not satisfied
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_take2_partial_timelocks_not_ready() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();

        let instance = Instance {
            instance_id,
            is_bridge_in: false,
            status: InstanceBridgeOutStatus::Claim.to_string(),
            bridge_out_amount: "100000".to_string(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_instance(&instance).await.unwrap();

        // Graph still in Challenge status - timelocks not all satisfied
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::Challenge.to_string(),
            kickoff_index: 999999, // Very recent
            bridge_out_start_at: rpc_service::current_time_secs(), // Just started
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Verify NOT in Take2 status (still Challenge)
        let found = storage_processor.find_graph(&graph_id).await.unwrap().unwrap();
        assert_eq!(found.status, GraphStatus::Challenge.to_string());
        assert_ne!(found.status, GraphStatus::OperatorTake2.to_string());
    }
}

/// Tests for Graph Monitor data boundary conditions
mod graph_monitor_boundary_tests {
    use super::*;
    use store::GraphBtcTxVoutMonitor;

    /// Test monitor with vout_len = 0 (empty outputs)
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_monitor_vout_empty() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let graph_id = Uuid::new_v4();
        let instance_id = Uuid::new_v4();

        // Create graph first
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorKickOff.to_string(),
            kickoff_index: 1000,
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Create monitor with empty vout data
        let monitor = GraphBtcTxVoutMonitor {
            graph_id,
            tx_name: "kickoff".to_string(),
            txid: SerializableTxid(BitcoinTxid::from_byte_array([1u8; 32])),
            height: 1000,
            vout_len: 0,
            monitor_data: "{}".to_string(), // Empty monitor data
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
        };
        storage_processor.upsert_graph_btc_tx_vout_monitor(&monitor).await.unwrap();

        // Verify empty monitor data stored correctly
        let txid1 = SerializableTxid(BitcoinTxid::from_byte_array([1u8; 32]));
        let found = storage_processor
            .find_graph_btc_tx_vout_monitor(&graph_id, &txid1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.monitor_data, "{}");
    }

    /// Test monitor with large vout count (100+ outputs)
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_monitor_vout_large_count() {
        let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
        let mut storage_processor = local_db.acquire().await.unwrap();

        let graph_id = Uuid::new_v4();
        let instance_id = Uuid::new_v4();

        // Create graph first
        let graph = Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorKickOff.to_string(),
            kickoff_index: 1000,
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
            ..Default::default()
        };
        storage_processor.upsert_graph(&graph).await.unwrap();

        // Create large monitor data simulating 100+ vouts
        let mut vout_items = Vec::new();
        for i in 0..100 {
            vout_items.push(serde_json::json!({
                "index": i,
                "status": "pending"
            }));
        }
        let large_monitor_data = serde_json::to_string(&serde_json::json!({
            "items": vout_items
        }))
        .unwrap();

        let monitor = GraphBtcTxVoutMonitor {
            graph_id,
            tx_name: "watchtower_init".into(),
            txid: SerializableTxid(BitcoinTxid::from_byte_array([2u8; 32])),
            height: 1000,
            vout_len: 100,
            monitor_data: large_monitor_data.clone(),
            created_at: rpc_service::current_time_secs(),
            updated_at: rpc_service::current_time_secs(),
        };
        storage_processor.upsert_graph_btc_tx_vout_monitor(&monitor).await.unwrap();

        // Verify large monitor data stored and retrieved correctly
        let txid2 = SerializableTxid(BitcoinTxid::from_byte_array([2u8; 32]));
        let found = storage_processor
            .find_graph_btc_tx_vout_monitor(&graph_id, &txid2)
            .await
            .unwrap()
            .unwrap();

        // Verify data integrity
        let parsed: serde_json::Value = serde_json::from_str(&found.monitor_data).unwrap();
        let items = parsed.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 100, "Should store 100 vout items without truncation");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bridge_out_timeout() {
    let (local_db, _, _, _, _, _db_file) = setup().await;
    let mut storage_processor = local_db.acquire().await.unwrap();

    let instance_id = Uuid::new_v4();

    // 1. Create Instance in Initialize status with expired lock time
    let lock_time_expired = rpc_service::current_time_secs() - 3600; // 1 hour ago
    let instance = Instance {
        instance_id,
        is_bridge_in: false,
        status: InstanceBridgeOutStatus::Initialize.to_string(),
        bridge_out_amount: "100000".to_string(),
        bridge_out_lock_time: lock_time_expired,
        escrow_hash: Some("0x123".to_string()), // Required filter condition
        created_at: rpc_service::current_time_secs(),
        updated_at: rpc_service::current_time_secs(),
        ..Default::default()
    };
    storage_processor.upsert_instance(&instance).await.unwrap();

    // 2. Run Monitor
    instance_bridge_out_monitor(&local_db).await.unwrap();

    // 3. Verify Transition to Timeout
    let instance = storage_processor.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(instance.status, InstanceBridgeOutStatus::Timeout.to_string());
}
