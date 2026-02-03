use alloy::primitives::{Address, B256, U256};
use alloy::sol_types::{SolCall, SolValue};
use bitvm2_lib::actors::Actor;
use bitvm2_noded::scheduled_tasks::event_watch_task;
use bitvm2_noded::utils::evm_swap_utils::IEscrowManager;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{
    SwapEventEntity, SwapInitializeEvent, SwapClaimEvent, SwapRefundEvent, TheGraphConfig,
    WatchEventConfig,
};
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
use serial_test::serial;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use store::InstanceBridgeOutStatus;
use store::localdb::InstanceQuery;
use store::create_local_db;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

mod test_support;
use test_support::{
    GraphMockState, clear_graph_mock_state, new_graph_mock_state, set_graph_mock_state,
    start_mock_graph_server_with_state,
};

fn test_config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    config.cases = env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    config.failure_persistence = None;
    config
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

fn build_initialize_event(escrow_hash: &str) -> SwapInitializeEvent {
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

fn build_claim_event(escrow_hash: &str) -> SwapClaimEvent {
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

fn build_refund_event(escrow_hash: &str) -> SwapRefundEvent {
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

fn setup_swap_traces(goat_client: &client::goat_chain::mock_goat_adaptor::MockAdaptor, swap_contract: Address, escrow_data: IEscrowManager::EscrowData) {
    let init_call = IEscrowManager::initializeCall {
        escrow: escrow_data.clone(),
        signature: alloy::primitives::Bytes::new(),
        timeout: U256::ZERO,
        _extraData: alloy::primitives::Bytes::new(),
    };
    let init_input = init_call.abi_encode();
    let init_trace = alloy::rpc::types::trace::geth::GethTrace::CallTracer(
        alloy::rpc::types::trace::geth::CallFrame {
            from: Address::ZERO,
            gas: U256::ZERO,
            gas_used: U256::ZERO,
            to: Some(swap_contract),
            input: init_input.into(),
            output: Some(alloy::primitives::Bytes::new()),
            error: None,
            revert_reason: None,
            calls: vec![],
            logs: vec![],
            value: Some(U256::ZERO),
            typ: "CALL".to_string(),
        },
    );
    goat_client.set_trace("0xinit".to_string(), init_trace);

    let mut witness = Vec::new();
    witness.extend_from_slice(&[0u8; 32]);
    witness.extend_from_slice(&1u32.to_be_bytes());
    witness.extend_from_slice(&[0u8; 20]);
    witness.extend_from_slice(&[0u8; 160]);
    witness.extend_from_slice(&0u32.to_be_bytes());
    let compressed = bitcoin::CompressedPublicKey::from_slice(&[
        0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
        0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
        0x88, 0x7e, 0x5b, 0x23, 0x52,
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
    let claim_trace = alloy::rpc::types::trace::geth::GethTrace::CallTracer(
        alloy::rpc::types::trace::geth::CallFrame {
            from: Address::ZERO,
            gas: U256::ZERO,
            gas_used: U256::ZERO,
            to: Some(swap_contract),
            input: claim_input.into(),
            output: Some(alloy::primitives::Bytes::new()),
            error: None,
            revert_reason: None,
            calls: vec![],
            logs: vec![],
            value: Some(U256::ZERO),
            typ: "CALL".to_string(),
        },
    );
    goat_client.set_trace("0xclaim".to_string(), claim_trace);
}

#[test]
#[serial]
fn prop_swap_initialize_claim_refund() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![
        Just((false, false)),
        Just((true, false)),
        Just((false, true)),
    ];

    runner
        .run(&strat, |(do_claim, do_refund)| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, goat_mock) = GOATClient::new_mock_client();
                let btc_client = Arc::new(btc_client);
                let goat_client = Arc::new(goat_client);

                let swap_contract = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
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

                let initializes = vec![build_initialize_event(&escrow_hash_hex)];
                let claims = if do_claim { vec![build_claim_event(&escrow_hash_hex)] } else { vec![] };
                let refunds = if do_refund { vec![build_refund_event(&escrow_hash_hex)] } else { vec![] };

                set_graph_mock_state(&graph_state, GraphMockState {
                    initializes: Some(serde_json::to_value(initializes).unwrap()),
                    claims: Some(serde_json::to_value(claims).unwrap()),
                    refunds: Some(serde_json::to_value(refunds).unwrap()),
                    ..Default::default()
                });

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;
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
                let client = GraphQueryClient::new();

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

                let instance = storage
                    .find_instances(InstanceQuery::default().with_is_bridge_in(false))
                    .await
                    .unwrap()
                    .0
                    .into_iter()
                    .next()
                    .unwrap();
                if do_refund {
                    assert_eq!(instance.status, InstanceBridgeOutStatus::Refund.to_string());
                } else if do_claim {
                    assert_eq!(instance.status, InstanceBridgeOutStatus::Claim.to_string());
                } else {
                    assert_eq!(instance.status, InstanceBridgeOutStatus::Initialize.to_string());
                }

                let stats = test_support::get_bridge_out_stats(&mut storage).await;
                let initial = U256::from_str(&stats.initial_amount).unwrap_or_default();
                let claim = U256::from_str(&stats.claim_amount).unwrap_or_default();
                let refund = U256::from_str(&stats.refund_amount).unwrap_or_default();
                assert!(claim + refund <= initial);
            });
            Ok(())
        })
        .unwrap();
}
