use bitvm2_lib::actors::Actor;
use bitvm2_noded::scheduled_tasks::event_watch_task;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{GatewayEventEntity, TheGraphConfig, WatchEventConfig};
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
use serial_test::serial;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use store::{
    GoatTxProcessingStatus, GoatTxRecord, GoatTxType, Graph, GraphStatus, Message, MessageState,
    Node,
};
use store::create_local_db;
use store::localdb::NodeQuery;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;
use uuid::Uuid;

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
    set_proof_server_url(None);
}

fn set_proof_server_url(value: Option<&str>) {
    unsafe {
        match value {
            Some(v) => env::set_var(bitvm2_noded::env::ENV_PROOF_SEVER_URL, v),
            None => env::remove_var(bitvm2_noded::env::ENV_PROOF_SEVER_URL),
        }
    }
}

fn gateway_config(graph_url: &str, entities: Vec<GatewayEventEntity>) -> WatchEventConfig {
    WatchEventConfig::Gateway(TheGraphConfig {
        address: alloy::primitives::Address::from_str("0x0000000000000000000000000000000000000000")
            .unwrap(),
        the_graph_url: graph_url.to_string(),
        event_entities: entities,
    })
}

fn build_graph(graph_id: Uuid, instance_id: Uuid) -> Graph {
    Graph {
        graph_id,
        instance_id,
        status: GraphStatus::OperatorPresigned.to_string(),
        init_withdraw_tx_hash: Some("0xold".to_string()),
        bridge_out_start_at: 123,
        created_at: 0,
        ..Default::default()
    }
}

fn build_node(peer_id: &str, goat_addr: &str) -> Node {
    Node {
        peer_id: peer_id.to_string(),
        actor: "Operator".to_string(),
        node_name: "node".to_string(),
        goat_addr: goat_addr.to_string(),
        btc_pub_key: "".to_string(),
        socket_addr: "".to_string(),
        service_fee_rate: 0.0,
        available_peg_btc: "0".to_string(),
        created_at: 0,
        updated_at: 0,
        ..Default::default()
    }
}

fn build_message(message_id: &str, business_id: Uuid) -> Message {
    Message {
        message_id: message_id.to_string(),
        business_id,
        actor: "Operator".to_string(),
        from_peer: "self".to_string(),
        msg_type: "test".to_string(),
        content: vec![],
        state: MessageState::Pending.to_string(),
        message_version: 0,
        weight: 0,
        lock_time_until: 0,
    }
}

#[test]
#[serial]
fn prop_withdraw_init_or_cancel_updates_graph() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |is_cancel| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let graph_id = test_support::test_fixtures::bridge_out_graph_id();
                let graph = build_graph(graph_id, instance_id);
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_graph(&mut storage, &graph).await;

                let instance_id_hex = test_support::test_fixtures::instance_id_hex();
                let graph_id_hex = test_support::test_fixtures::graph_id_hex();
                let init_events = if is_cancel {
                    serde_json::json!([])
                } else {
                    serde_json::json!([{
                        "id": "init_1",
                        "transactionHash": "0xinit",
                        "blockNumber": "10",
                        "instanceId": instance_id_hex,
                        "graphId": graph_id_hex
                    }])
                };
                let cancel_events = if is_cancel {
                    serde_json::json!([{
                        "id": "cancel_1",
                        "transactionHash": "0xcancel",
                        "blockNumber": "11",
                        "instanceId": instance_id_hex,
                        "graphId": graph_id_hex
                    }])
                } else {
                    serde_json::json!([])
                };
                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                    init_withdraws: Some(init_events),
                    cancel_withdraws: Some(cancel_events),
                    proceed_withdraws: Some(serde_json::json!([])),
                    withdraw_happy_paths: Some(serde_json::json!([])),
                    withdraw_unhappy_paths: Some(serde_json::json!([])),
                    withdraw_disproveds: Some(serde_json::json!([])),
                    ..Default::default()
                },
                );

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;
                let config = gateway_config(
                    &graph_url,
                    vec![GatewayEventEntity::InitWithdraws, GatewayEventEntity::CancelWithdraws],
                );
                let client = GraphQueryClient::new();

                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    Arc::new(btc_client),
                    Arc::new(goat_client),
                    &client,
                    &mut storage,
                    &config,
                    0,
                    20,
                )
                .await
                .unwrap();

                let updated = test_support::get_graph(&mut storage, &graph_id).await.unwrap();
                if is_cancel {
                    assert!(updated.init_withdraw_tx_hash.is_none());
                    assert_eq!(updated.bridge_out_start_at, 0);
                    let record = test_support::get_goat_tx(
                        &mut storage,
                        &instance_id,
                        &graph_id,
                        &GoatTxType::CancelWithdraw.to_string(),
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        record.processing_status,
                        GoatTxProcessingStatus::Skipped.to_string()
                    );
                } else {
                    assert_eq!(updated.init_withdraw_tx_hash, Some("0xinit".to_string()));
                    assert!(updated.bridge_out_start_at > 0);
                    let record = test_support::get_goat_tx(
                        &mut storage,
                        &instance_id,
                        &graph_id,
                        &GoatTxType::InitWithdraw.to_string(),
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        record.processing_status,
                        GoatTxProcessingStatus::Pending.to_string()
                    );
                }
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_withdraw_proceed_updates_graph_and_tx() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(1u8), Just(2u8)];

    runner
        .run(&strat, |_| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let graph_id = test_support::test_fixtures::bridge_out_graph_id();
                let graph = build_graph(graph_id, instance_id);
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_graph(&mut storage, &graph).await;

                let init_tx = GoatTxRecord {
                    instance_id,
                    graph_id,
                    tx_type: GoatTxType::InitWithdraw.to_string(),
                    tx_hash: "0xinit".to_string(),
                    height: 1,
                    is_local: false,
                    processing_status: GoatTxProcessingStatus::Pending.to_string(),
                    extra: None,
                    created_at: 0,
                };
                test_support::insert_goat_tx(&mut storage, &init_tx).await;

                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                    proceed_withdraws: Some(serde_json::json!([{
                        "id": "proceed_1",
                        "transactionHash": "0xproceed",
                        "blockNumber": "20",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "graphId": test_support::test_fixtures::graph_id_hex(),
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

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;
                let config = gateway_config(
                    &graph_url,
                    vec![GatewayEventEntity::ProceedWithdraws],
                );
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

                let updated = test_support::get_graph(&mut storage, &graph_id).await.unwrap();
                assert_eq!(updated.proceed_withdraw_height, 20);
                let proceed = test_support::get_goat_tx(
                    &mut storage,
                    &instance_id,
                    &graph_id,
                    &GoatTxType::ProceedWithdraw.to_string(),
                )
                .await
                .unwrap();
                assert_eq!(
                    proceed.processing_status,
                    GoatTxProcessingStatus::Pending.to_string()
                );
                let init = test_support::get_goat_tx(
                    &mut storage,
                    &instance_id,
                    &graph_id,
                    &GoatTxType::InitWithdraw.to_string(),
                )
                .await
                .unwrap();
                assert_eq!(
                    init.processing_status,
                    GoatTxProcessingStatus::Processed.to_string()
                );
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_withdraw_proceed_skipped_with_proof_server() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(1u8), Just(2u8)];

    runner
        .run(&strat, |_| {
            run_async(async move {
                setup_env();
                set_proof_server_url(Some("http://proof.local"));
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let graph_id = test_support::test_fixtures::bridge_out_graph_id();
                let graph = build_graph(graph_id, instance_id);
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_graph(&mut storage, &graph).await;

                let init_tx = GoatTxRecord {
                    instance_id,
                    graph_id,
                    tx_type: GoatTxType::InitWithdraw.to_string(),
                    tx_hash: "0xinit".to_string(),
                    height: 1,
                    is_local: false,
                    processing_status: GoatTxProcessingStatus::Pending.to_string(),
                    extra: None,
                    created_at: 0,
                };
                test_support::insert_goat_tx(&mut storage, &init_tx).await;

                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                    proceed_withdraws: Some(serde_json::json!([{
                        "id": "proceed_1",
                        "transactionHash": "0xproceed",
                        "blockNumber": "20",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "graphId": test_support::test_fixtures::graph_id_hex(),
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

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;
                let config = gateway_config(&graph_url, vec![GatewayEventEntity::ProceedWithdraws]);
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

                let proceed = test_support::get_goat_tx(
                    &mut storage,
                    &instance_id,
                    &graph_id,
                    &GoatTxType::ProceedWithdraw.to_string(),
                )
                .await
                .unwrap();
                assert_eq!(
                    proceed.processing_status,
                    GoatTxProcessingStatus::Skipped.to_string()
                );
                let init = test_support::get_goat_tx(
                    &mut storage,
                    &instance_id,
                    &graph_id,
                    &GoatTxType::InitWithdraw.to_string(),
                )
                .await
                .unwrap();
                assert_eq!(
                    init.processing_status,
                    GoatTxProcessingStatus::Processed.to_string()
                );
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_withdraw_paths_update_graph_reward_and_messages() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |is_happy| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let graph_id = test_support::test_fixtures::bridge_out_graph_id();
                let graph = build_graph(graph_id, instance_id);
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_graph(&mut storage, &graph).await;

                let operator_addr = "0x0000000000000000000000000000000000000001";
                let node = build_node("peer1", operator_addr);
                storage.upsert_node(&node).await.unwrap();
                let message = build_message("msg_1", graph_id);
                test_support::insert_message(&mut storage, &message).await;

                let reward = "1000";
                let happy_events = if is_happy {
                    serde_json::json!([{
                        "id": "happy_1",
                        "transactionHash": "0xhappy",
                        "blockNumber": "12",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "graphId": test_support::test_fixtures::graph_id_hex(),
                        "operatorAddress": operator_addr,
                        "rewardAmountSats": reward
                    }])
                } else {
                    serde_json::json!([])
                };
                let unhappy_events = if is_happy {
                    serde_json::json!([])
                } else {
                    serde_json::json!([{
                        "id": "unhappy_1",
                        "transactionHash": "0xunhappy",
                        "blockNumber": "13",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "graphId": test_support::test_fixtures::graph_id_hex(),
                        "operatorAddress": operator_addr,
                        "rewardAmountSats": reward
                    }])
                };
                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                    withdraw_happy_paths: Some(happy_events),
                    withdraw_unhappy_paths: Some(unhappy_events),
                    withdraw_disproveds: Some(serde_json::json!([])),
                    init_withdraws: Some(serde_json::json!([])),
                    cancel_withdraws: Some(serde_json::json!([])),
                    proceed_withdraws: Some(serde_json::json!([])),
                    ..Default::default()
                },
                );

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;
                let config = gateway_config(
                    &graph_url,
                    if is_happy {
                        vec![GatewayEventEntity::WithdrawHappyPaths]
                    } else {
                        vec![GatewayEventEntity::WithdrawUnhappyPaths]
                    },
                );
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

                let updated = test_support::get_graph(&mut storage, &graph_id).await.unwrap();
                if is_happy {
                    assert_eq!(updated.status, GraphStatus::OperatorTake1.to_string());
                } else {
                    assert_eq!(updated.status, GraphStatus::OperatorTake2.to_string());
                }
                let message = storage.find_messages_by_id("msg_1").await.unwrap().unwrap();
                assert_eq!(message.state, MessageState::Cancelled.to_string());
                let (nodes, _) = storage
                    .find_nodes(&NodeQuery::default().with_goat_addr(operator_addr.to_string()))
                    .await
                    .unwrap();
                let node = nodes.into_iter().next().unwrap();
                let reward_val =
                    alloy::primitives::U256::from_str(&node.reward).unwrap_or_default();
                assert_eq!(reward_val, alloy::primitives::U256::from(1000u64));
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_withdraw_disproved_updates_graph_reward_and_messages() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(1u8), Just(2u8)];

    runner
        .run(&strat, |_| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let graph_id = test_support::test_fixtures::bridge_out_graph_id();
                let graph = build_graph(graph_id, instance_id);
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_graph(&mut storage, &graph).await;

                let challenger_addr = "0x0000000000000000000000000000000000000002";
                let disprover_addr = "0x0000000000000000000000000000000000000003";
                storage.upsert_node(&build_node("peer2", challenger_addr)).await.unwrap();
                storage.upsert_node(&build_node("peer3", disprover_addr)).await.unwrap();
                let message = build_message("msg_2", graph_id);
                test_support::insert_message(&mut storage, &message).await;

                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                    withdraw_disproveds: Some(serde_json::json!([{
                        "id": "disprove_1",
                        "transactionHash": "0xdisprove",
                        "blockNumber": "20",
                        "blockTimestamp": "1600000100",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "graphId": test_support::test_fixtures::graph_id_hex(),
                        "disproveTxType": 1,
                        "txnIndex": "0",
                        "challengeStartTxid": "0xstart",
                        "challengeFinishTxid": "0xfinish",
                        "challengerAddress": challenger_addr,
                        "disproverAddress": disprover_addr,
                        "challengerRewardAmount": "500",
                        "disproverRewardAmount": "700"
                    }])),
                    init_withdraws: Some(serde_json::json!([])),
                    cancel_withdraws: Some(serde_json::json!([])),
                    proceed_withdraws: Some(serde_json::json!([])),
                    withdraw_happy_paths: Some(serde_json::json!([])),
                    withdraw_unhappy_paths: Some(serde_json::json!([])),
                    ..Default::default()
                },
                );

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;
                let config = gateway_config(
                    &graph_url,
                    vec![GatewayEventEntity::WithdrawDisproveds],
                );
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

                let updated = test_support::get_graph(&mut storage, &graph_id).await.unwrap();
                assert_eq!(updated.status, GraphStatus::Disprove.to_string());
                let message = storage.find_messages_by_id("msg_2").await.unwrap().unwrap();
                assert_eq!(message.state, MessageState::Cancelled.to_string());

                let (nodes, _) = storage
                    .find_nodes(&NodeQuery::default().with_goat_addr(challenger_addr.to_string()))
                    .await
                    .unwrap();
                let reward_val =
                    alloy::primitives::U256::from_str(&nodes[0].reward).unwrap_or_default();
                assert_eq!(reward_val, alloy::primitives::U256::from(500u64));
                let (nodes, _) = storage
                    .find_nodes(&NodeQuery::default().with_goat_addr(disprover_addr.to_string()))
                    .await
                    .unwrap();
                let reward_val =
                    alloy::primitives::U256::from_str(&nodes[0].reward).unwrap_or_default();
                assert_eq!(reward_val, alloy::primitives::U256::from(700u64));
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_withdraw_invalid_address_skips_updates() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |is_happy| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let graph_id = test_support::test_fixtures::bridge_out_graph_id();
                let graph = build_graph(graph_id, instance_id);
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_graph(&mut storage, &graph).await;

                let node = build_node("peer_invalid", "0x0000000000000000000000000000000000000001");
                storage.upsert_node(&node).await.unwrap();
                let message = build_message("msg_invalid", graph_id);
                test_support::insert_message(&mut storage, &message).await;

                let invalid_addr = "not_a_hex_address";
                let events = if is_happy {
                    serde_json::json!([{
                        "id": "happy_invalid",
                        "transactionHash": "0xhappy",
                        "blockNumber": "12",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "graphId": test_support::test_fixtures::graph_id_hex(),
                        "operatorAddress": invalid_addr,
                        "rewardAmountSats": "1000"
                    }])
                } else {
                    serde_json::json!([{
                        "id": "disprove_invalid",
                        "transactionHash": "0xdisprove",
                        "blockNumber": "20",
                        "blockTimestamp": "1600000100",
                        "instanceId": test_support::test_fixtures::instance_id_hex(),
                        "graphId": test_support::test_fixtures::graph_id_hex(),
                        "disproveTxType": 1,
                        "txnIndex": "0",
                        "challengeStartTxid": "0xstart",
                        "challengeFinishTxid": "0xfinish",
                        "challengerAddress": invalid_addr,
                        "disproverAddress": invalid_addr,
                        "challengerRewardAmount": "500",
                        "disproverRewardAmount": "700"
                    }])
                };
                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                    withdraw_happy_paths: Some(if is_happy { events.clone() } else { serde_json::json!([]) }),
                    withdraw_unhappy_paths: Some(serde_json::json!([])),
                    withdraw_disproveds: Some(if is_happy { serde_json::json!([]) } else { events }),
                    init_withdraws: Some(serde_json::json!([])),
                    cancel_withdraws: Some(serde_json::json!([])),
                    proceed_withdraws: Some(serde_json::json!([])),
                    ..Default::default()
                },
                );

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;
                let config = gateway_config(
                    &graph_url,
                    if is_happy {
                        vec![GatewayEventEntity::WithdrawHappyPaths]
                    } else {
                        vec![GatewayEventEntity::WithdrawDisproveds]
                    },
                );
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

                let updated = test_support::get_graph(&mut storage, &graph_id).await.unwrap();
                assert_eq!(updated.status, GraphStatus::OperatorPresigned.to_string());
                let msg = storage.find_messages_by_id("msg_invalid").await.unwrap().unwrap();
                assert_eq!(msg.state, MessageState::Pending.to_string());
                let (nodes, _) = storage
                    .find_nodes(&NodeQuery::default().with_goat_addr(node.goat_addr.clone()))
                    .await
                    .unwrap();
                let reward_val =
                    alloy::primitives::U256::from_str(&nodes[0].reward).unwrap_or_default();
                assert_eq!(reward_val, alloy::primitives::U256::ZERO);
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_withdraw_init_cancel_out_of_order() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(1u8), Just(2u8)];

    runner
        .run(&strat, |_| {
            run_async(async move {
                setup_env();
                let graph_state = new_graph_mock_state();
                clear_graph_mock_state(&graph_state);
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();

                let instance_id = test_support::test_fixtures::bridge_in_instance_id();
                let graph_id = test_support::test_fixtures::bridge_out_graph_id();
                let graph = build_graph(graph_id, instance_id);
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_graph(&mut storage, &graph).await;

                let instance_id_hex = test_support::test_fixtures::instance_id_hex();
                let graph_id_hex = test_support::test_fixtures::graph_id_hex();

                set_graph_mock_state(
                    &graph_state,
                    GraphMockState {
                    init_withdraws: Some(serde_json::json!([{
                        "id": "init_1",
                        "transactionHash": "0xinit",
                        "blockNumber": "10",
                        "instanceId": instance_id_hex,
                        "graphId": graph_id_hex
                    }])),
                    cancel_withdraws: Some(serde_json::json!([{
                        "id": "cancel_1",
                        "transactionHash": "0xcancel",
                        "blockNumber": "9",
                        "instanceId": instance_id_hex,
                        "graphId": graph_id_hex
                    }])),
                    proceed_withdraws: Some(serde_json::json!([])),
                    withdraw_happy_paths: Some(serde_json::json!([])),
                    withdraw_unhappy_paths: Some(serde_json::json!([])),
                    withdraw_disproveds: Some(serde_json::json!([])),
                    ..Default::default()
                },
                );

                let graph_url = start_mock_graph_server_with_state(graph_state.clone()).await;
                let config = gateway_config(
                    &graph_url,
                    vec![GatewayEventEntity::InitWithdraws, GatewayEventEntity::CancelWithdraws],
                );
                let client = GraphQueryClient::new();

                event_watch_task::fetch_and_handle_block_range_events(
                    Actor::Operator,
                    Arc::new(btc_client),
                    Arc::new(goat_client),
                    &client,
                    &mut storage,
                    &config,
                    0,
                    20,
                )
                .await
                .unwrap();

                let updated = test_support::get_graph(&mut storage, &graph_id).await.unwrap();
                assert_eq!(updated.init_withdraw_tx_hash, Some("0xinit".to_string()));
                assert!(updated.bridge_out_start_at > 0);
                let init = test_support::get_goat_tx(
                    &mut storage,
                    &instance_id,
                    &graph_id,
                    &GoatTxType::InitWithdraw.to_string(),
                )
                .await
                .unwrap();
                assert_eq!(
                    init.processing_status,
                    GoatTxProcessingStatus::Pending.to_string()
                );
                let cancel = test_support::get_goat_tx(
                    &mut storage,
                    &instance_id,
                    &graph_id,
                    &GoatTxType::CancelWithdraw.to_string(),
                )
                .await
                .unwrap();
                assert_eq!(
                    cancel.processing_status,
                    GoatTxProcessingStatus::Skipped.to_string()
                );
            });
            Ok(())
        })
        .unwrap();
}
