use bitvm2_lib::actors::Actor;
use bitcoin::hashes::Hash;
use bitvm2_noded::scheduled_tasks::event_watch_task;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{
    CommitteeResponseEvent, GatewayEventEntity, TheGraphConfig, WatchEventConfig,
};
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
use serial_test::serial;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use store::{GoatTxProcessingStatus, GoatTxRecord, GoatTxType, GraphStatus, InstanceBridgeInStatus};
use store::create_local_db;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;
use uuid::Uuid;

mod test_support;
use test_support::{GraphMockState, set_graph_mock_state, clear_graph_mock_state};

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
        env::set_var(bitvm2_noded::env::ENV_GOAT_SWAP_CONTRACT_ADDRESS, "0x0000000000000000000000000000000000000000");
        env::set_var(bitvm2_noded::env::ENV_BITCOIN_NETWORK, "regtest");
    }
}

fn setup_goat_pegin_data(
    goat_mock: &client::goat_chain::mock_goat_adaptor::MockAdaptor,
    instance_id_hex: &str,
) {
    let instance_id = uuid::Uuid::from_str(&instance_id_hex.trim_start_matches("0x")).unwrap();
    let btc_addr = test_support::valid_btc_address();
    let pegin_data = client::goat_chain::PeginData {
        status: client::goat_chain::PeginStatus::Pending,
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats: 100000,
        created_at: 1,
        pegin_txid: [0u8; 32],
        user_inputs: vec![client::goat_chain::Utxo {
            txid: [1u8; 32],
            vout: 0,
            amount_sats: 100000,
        }],
        committee_addresses: vec![[4u8; 20].into()],
        committee_pubkeys: vec![vec![2u8; 33]],
        user_xonly_pubkey: [2u8; 32],
        user_change_addr: btc_addr.clone(),
        user_refund_addr: btc_addr,
        txn_fees: [100, 100, 100],
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);
}

fn setup_btc_tx(
    btc_mock: &client::btc_chain::mock_bitcoin_adaptor::MockBitcoinAdaptor,
    txid: bitcoin::Txid,
) {
    let user_change_address = bitcoin::Address::p2wpkh(
        &bitcoin::CompressedPublicKey::from_slice(&[2u8; 33]).unwrap(),
        bitcoin::Network::Regtest,
    );
    let tx = esplora_client::Tx {
        txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![esplora_client::Vout { scriptpubkey: user_change_address.script_pubkey(), value: 200000 }],
        fee: 100,
        size: 100,
        weight: 400,
        status: esplora_client::TxStatus {
            confirmed: true,
            block_height: Some(1),
            block_hash: None,
            block_time: None,
        },
    };
    btc_mock.set_tx(txid, tx);
}

fn gateway_config(graph_url: &str) -> WatchEventConfig {
    WatchEventConfig::Gateway(TheGraphConfig {
        address: alloy::primitives::Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
        the_graph_url: graph_url.to_string(),
        event_entities: vec![
            GatewayEventEntity::BridgeInRequests,
            GatewayEventEntity::BridgeIns,
            GatewayEventEntity::CommitteeResponses,
            GatewayEventEntity::PostGraphDatas,
        ],
    })
}

#[test]
#[serial]
fn prop_bridge_in_request_creates_goat_tx() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(0u8), Just(1u8)];

    runner
        .run(&strat, |empty_flag| {
            run_async(async move {
                setup_env();
                clear_graph_mock_state();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id_hex = test_support::test_fixtures::instance_id_hex();
                let events = if empty_flag == 0 {
                    vec![]
                } else {
                    vec![serde_json::json!({
                        "id": "req_1",
                        "transactionHash": "0xbridge_in_req_tx",
                        "blockNumber": "10",
                        "blockTimestamp": "1600000000",
                        "instanceId": instance_id_hex,
                        "depositorAddress": "0x0000000000000000000000000000000000000100",
                        "peginAmountSats": "100000",
                        "txnFees": ["100", "100", "100"],
                        "userXonlyPubkey": "0x".to_string() + &"02".repeat(32),
                        "userChangeAddress": test_support::valid_btc_address(),
                        "userRefundAddress": test_support::valid_btc_address(),
                    })]
                };
                set_graph_mock_state(GraphMockState {
                    bridge_in_requests: Some(serde_json::Value::Array(events)),
                    bridge_ins: Some(serde_json::json!([])),
                    committee_responses: Some(serde_json::json!([])),
                    post_graph_datas: Some(serde_json::json!([])),
                    ..Default::default()
                });

                let graph_url = test_support::start_mock_graph_server().await;
                let config = gateway_config(&graph_url);
                let client = GraphQueryClient::new();

                let mut storage = local_db.acquire().await.unwrap();
                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    Arc::new(btc_client),
                    Arc::new(goat_client),
                    &client,
                    &mut storage,
                    &config,
                    0,
                    10,
                )
                .await
                .unwrap();

                if empty_flag == 0 {
                    let record = test_support::get_goat_tx(
                        &mut storage,
                        &Uuid::from_str(&instance_id_hex.trim_start_matches("0x")).unwrap(),
                        &Uuid::nil(),
                        &GoatTxType::BridgeInRequest.to_string(),
                    )
                    .await;
                    assert!(record.is_none());
                } else {
                    let record = test_support::get_goat_tx(
                        &mut storage,
                        &Uuid::from_str(&instance_id_hex.trim_start_matches("0x")).unwrap(),
                        &Uuid::nil(),
                        &GoatTxType::BridgeInRequest.to_string(),
                    )
                    .await;
                    assert!(record.is_some());
                }
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_committee_response_updates_instance() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(1u8), Just(2u8)];

    runner
        .run(&strat, |committee_count| {
            run_async(async move {
                setup_env();
                clear_graph_mock_state();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let instance = store::Instance {
                    instance_id,
                    is_bridge_in: true,
                    network: "regtest".to_string(),
                    status: InstanceBridgeInStatus::UserInited.to_string(),
                    created_at: 0,
                    ..Default::default()
                };
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_instance(&mut storage, &instance).await;

                let instance_id_hex = test_support::test_fixtures::instance_id_hex();
                let mut responses: Vec<CommitteeResponseEvent> = vec![];
                for i in 0..committee_count {
                    responses.push(CommitteeResponseEvent {
                        id: format!("resp_{i}"),
                        transaction_hash: "0xresp".to_string(),
                        block_number: "10".to_string(),
                        instance_id: instance_id_hex.clone(),
                        committee_address: format!("0x{:040x}", i + 1),
                        committee_pubkey: hex::encode([2u8; 33]),
                    });
                }
                set_graph_mock_state(GraphMockState {
                    committee_responses: Some(serde_json::to_value(responses).unwrap()),
                    bridge_in_requests: Some(serde_json::json!([])),
                    bridge_ins: Some(serde_json::json!([])),
                    post_graph_datas: Some(serde_json::json!([])),
                    ..Default::default()
                });

                let graph_url = test_support::start_mock_graph_server().await;
                let config = gateway_config(&graph_url);
                let client = GraphQueryClient::new();
                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    Arc::new(btc_client),
                    Arc::new(goat_client),
                    &client,
                    &mut storage,
                    &config,
                    0,
                    10,
                )
                .await
                .unwrap();

                let updated = test_support::get_instance(&mut storage, &instance_id).await.unwrap();
                assert_eq!(updated.committees_answers.len(), committee_count as usize);
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_post_graph_data_updates_status() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |has_graph| {
            run_async(async move {
                setup_env();
                clear_graph_mock_state();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let graph_id = test_support::test_fixtures::bridge_out_graph_id();
                if has_graph {
                    let graph = store::Graph {
                        graph_id,
                        instance_id: test_support::test_fixtures::bridge_in_instance_id(),
                        status: GraphStatus::OperatorPresigned.to_string(),
                        created_at: 0,
                        ..Default::default()
                    };
                    let mut storage = local_db.acquire().await.unwrap();
                    test_support::insert_graph(&mut storage, &graph).await;
                }

                set_graph_mock_state(GraphMockState {
                    post_graph_datas: Some(serde_json::json!([{
                        "id": "post_1",
                        "transactionHash": "0xpost",
                        "blockNumber": "10",
                        "blockTimestamp": "1600000000",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "graphId": test_support::test_fixtures::graph_id_hex(),
                    }])),
                    bridge_in_requests: Some(serde_json::json!([])),
                    bridge_ins: Some(serde_json::json!([])),
                    committee_responses: Some(serde_json::json!([])),
                    ..Default::default()
                });

                let graph_url = test_support::start_mock_graph_server().await;
                let config = gateway_config(&graph_url);
                let client = GraphQueryClient::new();

                let mut storage = local_db.acquire().await.unwrap();
                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    Arc::new(btc_client),
                    Arc::new(goat_client),
                    &client,
                    &mut storage,
                    &config,
                    0,
                    10,
                )
                .await
                .unwrap();

                let updated = test_support::get_graph(&mut storage, &graph_id).await;
                if has_graph {
                    assert_eq!(updated.unwrap().status, GraphStatus::OperatorDataPushed.to_string());
                } else {
                    assert!(updated.is_none());
                }
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_bridge_in_history_creates_instance() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(1u8), Just(2u8)];

    runner
        .run(&strat, |_| {
            run_async(async move {
                setup_env();
                clear_graph_mock_state();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, btc_mock) = BTCClient::new_mock_client();
                let (goat_client, goat_mock) = GOATClient::new_mock_client();

                let instance_id_hex = test_support::test_fixtures::instance_id_hex();
                setup_goat_pegin_data(&goat_mock, &instance_id_hex);

                let btc_txid = bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
                setup_btc_tx(&btc_mock, btc_txid);

                let bridge_in_req = serde_json::json!({
                    "id": "req_1",
                    "transactionHash": "0xbridge_in_req_tx",
                    "blockNumber": "10",
                    "blockTimestamp": "1600000000",
                    "instanceId": instance_id_hex,
                    "depositorAddress": "0x0000000000000000000000000000000000000100",
                    "peginAmountSats": "100000",
                    "txnFees": ["100", "100", "100"],
                    "userXonlyPubkey": "0x".to_string() + &"02".repeat(32),
                    "userChangeAddress": test_support::valid_btc_address(),
                    "userRefundAddress": test_support::valid_btc_address(),
                });
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_goat_tx(
                    &mut storage,
                    &GoatTxRecord {
                        instance_id: uuid::Uuid::from_str(&instance_id_hex.trim_start_matches("0x")).unwrap(),
                        graph_id: Uuid::nil(),
                        tx_type: GoatTxType::BridgeInRequest.to_string(),
                        tx_hash: "0xbridge_in_req_tx".to_string(),
                        height: 10,
                        is_local: false,
                        processing_status: GoatTxProcessingStatus::Pending.to_string(),
                        extra: Some(serde_json::to_string(&bridge_in_req).unwrap()),
                        created_at: 0,
                    },
                )
                .await;

                set_graph_mock_state(GraphMockState {
                    bridge_ins: Some(serde_json::json!([{
                        "id": "bridge_in_1",
                        "transactionHash": "0xbridge_in_tx",
                        "blockNumber": "20",
                        "instanceId": instance_id_hex,
                        "depositorAddress": "0xdepositor",
                        "peginAmountSats": "100000",
                        "feeAmountSats": "1000"
                    }])),
                    bridge_in_requests: Some(serde_json::json!([])),
                    committee_responses: Some(serde_json::json!([])),
                    post_graph_datas: Some(serde_json::json!([])),
                    ..Default::default()
                });

                let graph_url = test_support::start_mock_graph_server().await;
                let config = gateway_config(&graph_url);
                let client = GraphQueryClient::new();

                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    Arc::new(btc_client),
                    Arc::new(goat_client),
                    &client,
                    &mut storage,
                    &config,
                    0,
                    30,
                )
                .await
                .unwrap();

                let instance_id = uuid::Uuid::from_str(&instance_id_hex.trim_start_matches("0x")).unwrap();
                let instance = test_support::get_instance(&mut storage, &instance_id).await.unwrap();
                assert_eq!(
                    instance.status,
                    InstanceBridgeInStatus::RelayerL2Minted.to_string()
                );
                let record = test_support::get_goat_tx(
                    &mut storage,
                    &instance_id,
                    &Uuid::nil(),
                    &GoatTxType::BridgeInRequest.to_string(),
                )
                .await
                .unwrap();
                assert_eq!(
                    record.processing_status,
                    GoatTxProcessingStatus::Skipped.to_string()
                );
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_bridge_in_updates_existing_instance() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(1u8), Just(2u8)];

    runner
        .run(&strat, |_| {
            run_async(async move {
                setup_env();
                clear_graph_mock_state();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_instance(
                    &mut storage,
                    &store::Instance {
                        instance_id,
                        is_bridge_in: true,
                        network: "regtest".to_string(),
                        status: InstanceBridgeInStatus::UserInited.to_string(),
                        created_at: 0,
                        ..Default::default()
                    },
                )
                .await;

                set_graph_mock_state(GraphMockState {
                    bridge_ins: Some(serde_json::json!([{
                        "id": "bridge_in_1",
                        "transactionHash": "0xbridge_in_tx",
                        "blockNumber": "20",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "depositorAddress": "0xdepositor",
                        "peginAmountSats": "100000",
                        "feeAmountSats": "1000"
                    }])),
                    bridge_in_requests: Some(serde_json::json!([])),
                    committee_responses: Some(serde_json::json!([])),
                    post_graph_datas: Some(serde_json::json!([])),
                    ..Default::default()
                });

                let graph_url = test_support::start_mock_graph_server().await;
                let config = gateway_config(&graph_url);
                let client = GraphQueryClient::new();

                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    Arc::new(btc_client),
                    Arc::new(goat_client),
                    &client,
                    &mut storage,
                    &config,
                    0,
                    30,
                )
                .await
                .unwrap();

                let instance = test_support::get_instance(&mut storage, &instance_id).await.unwrap();
                assert_eq!(
                    instance.status,
                    InstanceBridgeInStatus::RelayerL2Minted.to_string()
                );
                assert_eq!(instance.post_pegin_txhash, Some("0xbridge_in_tx".to_string()));
            });
            Ok(())
        })
        .unwrap();
}
