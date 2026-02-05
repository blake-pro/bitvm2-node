use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::rpc::types::trace::geth::{CallFrame, GethTrace};
use alloy::sol_types::{SolCall, SolValue};
use bitvm2_lib::actors::Actor;
use bitvm2_noded::scheduled_tasks::event_watch_task;
use bitvm2_noded::utils::evm_swap_utils::IEscrowManager;
use client::btc_chain::{BTCClient, mock_bitcoin_adaptor::MockBitcoinAdaptor};
use client::goat_chain::mock_goat_adaptor::MockAdaptor;
use client::goat_chain::{GOATClient, PeginData, PeginStatus, Utxo as GoatUtxo};
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{
    BridgeInEvent, BridgeInRequestEvent, GatewayEventEntity, SwapClaimEvent, SwapEventEntity,
    SwapInitializeEvent, SwapRefundEvent, TheGraphConfig, WatchEventConfig,
};
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
use serial_test::serial;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use store::create_local_db;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

mod test_support;
use test_support::{
    GraphMockState, clear_graph_mock_state, new_graph_mock_state, set_graph_mock_state,
    start_mock_graph_server_with_state,
};

fn test_config() -> ProptestConfig {
    ProptestConfig {
        cases: env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(100),
        failure_persistence: None,
        ..Default::default()
    }
}

fn build_test_runner() -> TestRunner {
    let config = test_config();
    if let Some(seed) = env::var("PROPTEST_SEED").ok().and_then(|s| s.parse::<u64>().ok()) {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed_bytes);
        TestRunner::new_with_rng(config, rng)
    } else {
        TestRunner::new(config)
    }
}

fn run_async<F: std::future::Future<Output = ()>>(fut: F) {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(fut);
}

fn build_bridge_in_request_event(instance_id_hex: &str) -> BridgeInRequestEvent {
    let user_xonly_pubkey = format!("0x{}", "02".repeat(32));
    let btc_addr = valid_btc_address();
    BridgeInRequestEvent {
        id: "req_1".to_string(),
        transaction_hash: "0xbridge_in_req_tx".to_string(),
        block_number: "10".to_string(),
        block_timestamp: "1600000000".to_string(),
        instance_id: instance_id_hex.to_string(),
        depositor_address: "0x0000000000000000000000000000000000000100".to_string(),
        pegin_amount_sats: "100000".to_string(),
        txn_fees: ["100".to_string(), "100".to_string(), "100".to_string()],
        user_xonly_pubkey,
        user_change_address: btc_addr.clone(),
        user_refund_address: btc_addr,
    }
}

fn build_bridge_in_event(instance_id_hex: &str) -> BridgeInEvent {
    BridgeInEvent {
        id: "bridge_in_1".to_string(),
        transaction_hash: "0xbridge_in_tx".to_string(),
        block_number: "20".to_string(),
        instance_id: instance_id_hex.to_string(),
        depositor_address: "0xdepositor".to_string(),
        pegin_amount_sats: "100000".to_string(),
        fee_amount_sats: "1000".to_string(),
    }
}

fn build_swap_initialize_event(escrow_hash: &str) -> SwapInitializeEvent {
    SwapInitializeEvent {
        id: "init_1".to_string(),
        transaction_hash: "0xinit".to_string(),
        block_number: "1".to_string(),
        block_timestamp: "1000".to_string(),
        offerer: "0x0000000000000000000000000000000000000000".to_string(),
        claimer: "0x0000000000000000000000000000000000000000".to_string(),
        escrow_hash: escrow_hash.to_string(),
        claim_handler: "0x0000000000000000000000000000000000000000".to_string(),
        refund_handler: "0x0000000000000000000000000000000000000000".to_string(),
    }
}

fn build_swap_claim_event(escrow_hash: &str) -> SwapClaimEvent {
    SwapClaimEvent {
        id: "claim_1".to_string(),
        transaction_hash: "0xclaim".to_string(),
        block_number: "2".to_string(),
        offerer: "0x0000000000000000000000000000000000000000".to_string(),
        claimer: "0x0000000000000000000000000000000000000000".to_string(),
        escrow_hash: escrow_hash.to_string(),
        claim_handler: "0x0000000000000000000000000000000000000000".to_string(),
        witness_result: "0x".to_string(),
    }
}

fn build_swap_refund_event(escrow_hash: &str) -> SwapRefundEvent {
    SwapRefundEvent {
        id: "refund_1".to_string(),
        transaction_hash: "0xrefund".to_string(),
        block_number: "3".to_string(),
        offerer: "0x0000000000000000000000000000000000000000".to_string(),
        claimer: "0x0000000000000000000000000000000000000000".to_string(),
        escrow_hash: escrow_hash.to_string(),
        refund_handler: "0x0000000000000000000000000000000000000000".to_string(),
        witness_result: "0x".to_string(),
    }
}

fn setup_clients() -> (Arc<BTCClient>, MockBitcoinAdaptor, Arc<GOATClient>, MockAdaptor) {
    let (btc_client, btc_mock) = BTCClient::new_mock_client();
    let (goat_client, goat_mock) = GOATClient::new_mock_client();
    (Arc::new(btc_client), btc_mock, Arc::new(goat_client), goat_mock)
}

fn setup_goat_pegin_data(goat_mock: &MockAdaptor, instance_id_hex: &str) {
    let instance_id = uuid::Uuid::from_str(instance_id_hex.trim_start_matches("0x")).unwrap();
    let btc_addr = valid_btc_address();
    let input_txid = [1u8; 32];
    let pegin_data = PeginData {
        status: PeginStatus::Pending,
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats: 100000,
        created_at: 1,
        pegin_txid: [0u8; 32],
        user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: 100000 }],
        committee_addresses: vec![[4u8; 20].into()],
        committee_pubkeys: vec![vec![2u8; 33]],
        user_xonly_pubkey: [2u8; 32],
        user_change_addr: btc_addr.clone(),
        user_refund_addr: btc_addr,
        txn_fees: [100, 100, 100],
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);
}

fn setup_swap_traces(
    goat_mock: &MockAdaptor,
    swap_contract: Address,
    escrow_data: IEscrowManager::EscrowData,
) {
    let init_call = IEscrowManager::initializeCall {
        escrow: escrow_data.clone(),
        signature: Bytes::new(),
        timeout: U256::ZERO,
        _extraData: Bytes::new(),
    };
    let init_input = init_call.abi_encode();
    let init_trace = GethTrace::CallTracer(CallFrame {
        from: Address::ZERO,
        gas: U256::ZERO,
        gas_used: U256::ZERO,
        to: Some(swap_contract),
        input: init_input.into(),
        output: Some(Bytes::new()),
        error: None,
        revert_reason: None,
        calls: vec![],
        logs: vec![],
        value: Some(U256::ZERO),
        typ: "CALL".to_string(),
    });
    goat_mock.set_trace("0xinit".to_string(), init_trace);

    let mut witness = Vec::new();
    witness.extend_from_slice(&[0u8; 32]);
    witness.extend_from_slice(&1u32.to_be_bytes());
    witness.extend_from_slice(&[0u8; 20]);
    witness.extend_from_slice(&[0u8; 160]);
    witness.extend_from_slice(&0u32.to_be_bytes());
    let compressed = bitcoin::CompressedPublicKey::from_slice(&[
        0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8,
        0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88, 0x7e,
        0x5b, 0x23, 0x52,
    ])
    .unwrap();
    let to_addr = bitcoin::Address::p2wpkh(&compressed, bitvm2_noded::env::get_network());
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn::default()],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100000),
            script_pubkey: to_addr.script_pubkey(),
        }],
    };
    let tx_bytes = bitcoin::consensus::serialize(&tx);
    let tx_len = U256::from(tx_bytes.len());
    witness.extend_from_slice(&tx_len.to_be_bytes::<32>());
    witness.extend_from_slice(&tx_bytes);
    let claim_call = IEscrowManager::claimCall { escrow: escrow_data, witness: witness.into() };
    let claim_input = claim_call.abi_encode();
    let claim_trace = GethTrace::CallTracer(CallFrame {
        from: Address::ZERO,
        gas: U256::ZERO,
        gas_used: U256::ZERO,
        to: Some(swap_contract),
        input: claim_input.into(),
        output: Some(Bytes::new()),
        error: None,
        revert_reason: None,
        calls: vec![],
        logs: vec![],
        value: Some(U256::ZERO),
        typ: "CALL".to_string(),
    });
    goat_mock.set_trace("0xclaim".to_string(), claim_trace);
}

fn valid_btc_address() -> String {
    let compressed = bitcoin::CompressedPublicKey::from_slice(&[
        0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8,
        0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88, 0x7e,
        0x5b, 0x23, 0x52,
    ])
    .unwrap();
    bitcoin::Address::p2wpkh(&compressed, bitvm2_noded::env::get_network()).to_string()
}

fn setup_env() {
    unsafe {
        env::set_var(
            bitvm2_noded::env::ENV_GOAT_GATEWAY_CONTRACT_ADDRESS,
            "0x0000000000000000000000000000000000000000",
        );
        env::set_var(
            bitvm2_noded::env::ENV_GOAT_SWAP_CONTRACT_ADDRESS,
            "0x0000000000000000000000000000000000000000",
        );
        env::set_var(bitvm2_noded::env::ENV_BITCOIN_NETWORK, "regtest");
    }
}

#[test]
#[serial]
fn property_bridge_out_stats_conservation() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just((0u8, 0u8)), Just((1u8, 0u8)), Just((0u8, 1u8)),];

    runner
        .run(&strat, |(claim_count, refund_count)| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db =
                    create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock, goat_client, goat_mock) = setup_clients();

                let swap_contract =
                    Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
                let escrow_data = IEscrowManager::EscrowData {
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
                let escrow_hash_hex = format!("0x{}", hex::encode(escrow_hash.0));

                setup_swap_traces(&goat_mock, swap_contract, escrow_data.clone());

                let initializes = vec![build_swap_initialize_event(&escrow_hash_hex)];
                let mut claims = Vec::new();
                for _ in 0..claim_count {
                    claims.push(build_swap_claim_event(&escrow_hash_hex));
                }
                let mut refunds = Vec::new();
                for _ in 0..refund_count {
                    refunds.push(build_swap_refund_event(&escrow_hash_hex));
                }

                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                        initializes: Some(serde_json::to_value(initializes).unwrap()),
                        claims: Some(serde_json::to_value(claims).unwrap()),
                        refunds: Some(serde_json::to_value(refunds).unwrap()),
                        bridge_in_requests: None,
                        bridge_ins: None,
                        ..Default::default()
                    },
                );

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;

                let client = GraphQueryClient::new();
                let config_init = WatchEventConfig::Swap(TheGraphConfig {
                    address: swap_contract,
                    the_graph_url: graph_url.clone(),
                    event_entities: vec![SwapEventEntity::Initializes],
                });
                let config_claim = WatchEventConfig::Swap(TheGraphConfig {
                    address: swap_contract,
                    the_graph_url: graph_url.clone(),
                    event_entities: vec![SwapEventEntity::Claims],
                });
                let config_refund = WatchEventConfig::Swap(TheGraphConfig {
                    address: swap_contract,
                    the_graph_url: graph_url.clone(),
                    event_entities: vec![SwapEventEntity::Refunds],
                });

                let mut storage = local_db.acquire().await.unwrap();
                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    btc_client.clone(),
                    goat_client.clone(),
                    &client,
                    &mut storage,
                    &config_init,
                    0,
                    10,
                )
                .await
                .unwrap();
                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    btc_client.clone(),
                    goat_client.clone(),
                    &client,
                    &mut storage,
                    &config_claim,
                    11,
                    20,
                )
                .await
                .unwrap();
                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    btc_client.clone(),
                    goat_client.clone(),
                    &client,
                    &mut storage,
                    &config_refund,
                    21,
                    30,
                )
                .await
                .unwrap();

                let mut storage = local_db.acquire().await.unwrap();
                let stats =
                    storage.find_bridge_out_global_stats_by_id(1).await.unwrap().unwrap_or_else(
                        || store::BridgeOutGlobalStats {
                            id: 1,
                            initial_txn: 0,
                            initial_amount: "0".to_string(),
                            claim_txn: 0,
                            claim_amount: "0".to_string(),
                            refund_txn: 0,
                            refund_amount: "0".to_string(),
                            created_at: 0,
                            updated_at: 0,
                        },
                    );
                let initial = U256::from_str(&stats.initial_amount).unwrap_or_default();
                let claim = U256::from_str(&stats.claim_amount).unwrap_or_default();
                let refund = U256::from_str(&stats.refund_amount).unwrap_or_default();
                assert!(claim + refund <= initial);
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn property_bridge_in_idempotency() {
    let mut runner = build_test_runner();
    let strat = 0u8..3u8;

    runner
        .run(&strat, |repeat_times| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db =
                    create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock, goat_client, goat_mock) = setup_clients();

                let instance_id_hex = test_support::test_fixtures::instance_id_hex();
                setup_goat_pegin_data(&goat_mock, &instance_id_hex);

                let bridge_in_req = build_bridge_in_request_event(&instance_id_hex);
                let bridge_in = build_bridge_in_event(&instance_id_hex);

                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                        initializes: None,
                        claims: None,
                        refunds: None,
                        bridge_in_requests: Some(
                            serde_json::to_value(vec![bridge_in_req]).unwrap(),
                        ),
                        bridge_ins: Some(serde_json::to_value(vec![bridge_in]).unwrap()),
                        ..Default::default()
                    },
                );

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;

                let client = GraphQueryClient::new();
                let config_gateway = WatchEventConfig::Gateway(TheGraphConfig {
                    address: Address::from_str("0x0000000000000000000000000000000000000000")
                        .unwrap(),
                    the_graph_url: graph_url.clone(),
                    event_entities: vec![
                        GatewayEventEntity::BridgeInRequests,
                        GatewayEventEntity::BridgeIns,
                    ],
                });

                for _ in 0..=repeat_times {
                    let mut storage = local_db.acquire().await.unwrap();
                    event_watch_task::fetch_and_handle_block_range_events(
                        Actor::Operator,
                        btc_client.clone(),
                        goat_client.clone(),
                        &client,
                        &mut storage,
                        &config_gateway,
                        0,
                        10,
                    )
                    .await
                    .unwrap();
                }

                let mut storage = local_db.acquire().await.unwrap();
                let instance_id =
                    uuid::Uuid::from_str(instance_id_hex.trim_start_matches("0x")).unwrap();
                let instance = storage.find_instance(&instance_id).await.unwrap();
                assert!(instance.is_some());
                assert_eq!(
                    instance.unwrap().status,
                    store::InstanceBridgeInStatus::RelayerL2Minted.to_string()
                );
            });
            Ok(())
        })
        .unwrap();
}
