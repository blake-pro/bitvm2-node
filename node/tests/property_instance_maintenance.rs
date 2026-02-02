use bitvm2_noded::scheduled_tasks::instance_maintenance_tasks::{
    instance_answers_monitor, instance_btc_tx_monitor, instance_expiration_monitor,
    instance_window_expiration_monitor,
};
use bitcoin::hashes::Hash;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
use serial_test::serial;
use std::env;
use std::str::FromStr;
use store::{Instance, InstanceBridgeInStatus};
use store::create_local_db;
use store::MessageType;
use store::localdb::InstanceQuery;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;
use uuid::Uuid;

mod test_support;

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
        env::set_var(bitvm2_noded::env::ENV_BITCOIN_NETWORK, "regtest");
    }
}

#[test]
#[serial]
fn prop_instance_expiration_boundary() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |should_expire| {
            run_async(async move {
                setup_env();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, btc_mock) = BTCClient::new_mock_client();

                let instance_id = Uuid::new_v4();
                let instance = Instance {
                    instance_id,
                    is_bridge_in: true,
                    network: "regtest".to_string(),
                    status: InstanceBridgeInStatus::Presigned.to_string(),
                    btc_height: 10,
                    input_utxos: "[]".to_string(),
                    created_at: 0,
                    ..Default::default()
                };
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_instance(&mut storage, &instance).await;

                let lock_height = bitvm2_lib::constants::CONNECTOR_Z_TIMELOCK as i64;
                let current_height = if should_expire {
                    instance.btc_height + lock_height + 1
                } else {
                    instance.btc_height + lock_height
                };
                btc_mock.set_height(current_height as u32);

                instance_expiration_monitor(&local_db, &btc_client).await.unwrap();
                let updated = test_support::get_instance(&mut storage, &instance_id).await.unwrap();
                if should_expire {
                    assert_eq!(updated.status, InstanceBridgeInStatus::Timeout.to_string());
                } else {
                    assert_eq!(updated.status, InstanceBridgeInStatus::Presigned.to_string());
                }
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_instance_btc_tx_monitor_confirmed_vs_unconfirmed() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |confirmed| {
            run_async(async move {
                setup_env();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, btc_mock) = BTCClient::new_mock_client();

                let instance_id = Uuid::new_v4();
                let txid = bitcoin::Txid::from_str(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap();
                let instance = Instance {
                    instance_id,
                    is_bridge_in: true,
                    network: "regtest".to_string(),
                    status: InstanceBridgeInStatus::CommitteesAnswered.to_string(),
                    btc_txid: Some(txid.into()),
                    input_utxos: "[]".to_string(),
                    created_at: 0,
                    ..Default::default()
                };
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_instance(&mut storage, &instance).await;

                let tx = esplora_client::Tx {
                    txid,
                    version: 2,
                    locktime: 0,
                    vin: vec![],
                    vout: vec![],
                    status: esplora_client::TxStatus {
                        confirmed,
                        block_height: if confirmed { Some(100) } else { None },
                        block_hash: None,
                        block_time: None,
                    },
                    fee: 100,
                    size: 100,
                    weight: 400,
                };
                btc_mock.set_tx(txid, tx);

                instance_btc_tx_monitor(&local_db, &btc_client).await.unwrap();
                let updated = test_support::get_instance(&mut storage, &instance_id).await.unwrap();
                if confirmed {
                    assert_eq!(
                        updated.status,
                        InstanceBridgeInStatus::UserBroadcastPeginPrepare.to_string()
                    );
                } else {
                    assert_eq!(
                        updated.status,
                        InstanceBridgeInStatus::CommitteesAnswered.to_string()
                    );
                }
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_instance_window_expiration_monitor_quorum() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |quorum_enough| {
            run_async(async move {
                setup_env();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (_btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, goat_mock) = GOATClient::new_mock_client();

                goat_mock.set_latest_block_number(200);
                goat_mock.set_finalized_block_number(200);
                goat_mock.set_quorum_size(if quorum_enough { 1 } else { 2 });

                let instance_id = Uuid::new_v4();
                let instance = Instance {
                    instance_id,
                    is_bridge_in: true,
                    network: "regtest".to_string(),
                    status: InstanceBridgeInStatus::UserInited.to_string(),
                    goat_tx_height: 1,
                    input_utxos: "[]".to_string(),
                    created_at: 0,
                    ..Default::default()
                };
                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_instance(&mut storage, &instance).await;

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

                instance_window_expiration_monitor(&local_db, &goat_client)
                    .await
                    .unwrap();
                let updated = test_support::get_instance(&mut storage, &instance_id).await.unwrap();
                if quorum_enough {
                    assert_eq!(
                        updated.status,
                        InstanceBridgeInStatus::CommitteesAnswered.to_string()
                    );
                } else {
                    assert_eq!(
                        updated.status,
                        InstanceBridgeInStatus::NoEnoughCommitteesAnswered.to_string()
                    );
                }
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_instance_answers_monitor_branches() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |outside_window| {
            run_async(async move {
                setup_env();
                let temp_db = NamedTempFile::new().unwrap();
                let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
                let (btc_client, btc_mock) = BTCClient::new_mock_client();
                let (goat_client, goat_mock) = GOATClient::new_mock_client();

                let instance_id = Uuid::new_v4();
                let instance_id_hex = format!("0x{}", instance_id.to_string().replace("-", ""));
                let bridge_req = client::graphs::graph_query::BridgeInRequestEvent {
                    id: "req_1".to_string(),
                    transaction_hash: "0xbridge_in_req_tx".to_string(),
                    block_number: "10".to_string(),
                    block_timestamp: "1600000000".to_string(),
                    instance_id: instance_id_hex.clone(),
                    depositor_address: "0x0000000000000000000000000000000000000100".to_string(),
                    pegin_amount_sats: "100000".to_string(),
                    txn_fees: ["100".to_string(), "100".to_string(), "100".to_string()],
                    user_xonly_pubkey: "0x".to_string() + &"02".repeat(32),
                    user_change_address: test_support::valid_btc_address(),
                    user_refund_address: test_support::valid_btc_address(),
                };

                let mut storage = local_db.acquire().await.unwrap();
                test_support::insert_goat_tx(
                    &mut storage,
                    &store::GoatTxRecord {
                        instance_id,
                        graph_id: Uuid::nil(),
                        tx_type: store::GoatTxType::BridgeInRequest.to_string(),
                        tx_hash: "0xbridge_in_req_tx".to_string(),
                        height: 10,
                        is_local: false,
                        processing_status: store::GoatTxProcessingStatus::Pending.to_string(),
                        extra: Some(serde_json::to_string(&bridge_req).unwrap()),
                        created_at: 0,
                    },
                )
                .await;

                if outside_window {
                    goat_mock.set_finalized_block_number(200);
                } else {
                    goat_mock.set_finalized_block_number(10);
                }

                let btc_addr = test_support::valid_btc_address();
                let input_txid = [1u8; 32];
                let pegin_data = client::goat_chain::PeginData {
                    status: client::goat_chain::PeginStatus::Pending,
                    instance_id: *instance_id.as_bytes(),
                    depositor_address: [0u8; 20],
                    pegin_amount_sats: 100000,
                    created_at: 1,
                    pegin_txid: [0u8; 32],
                    user_inputs: vec![client::goat_chain::Utxo {
                        txid: input_txid,
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

                if outside_window {
                    let input_txid_struct = bitcoin::Txid::from_byte_array(input_txid);
                    btc_mock.set_output_status(
                        input_txid_struct,
                        0,
                        esplora_client::OutputStatus {
                            spent: true,
                            txid: Some(bitcoin::Txid::from_byte_array([9u8; 32])),
                            vin: Some(0),
                            status: Some(esplora_client::TxStatus {
                                confirmed: true,
                                block_height: Some(100),
                                block_hash: None,
                                block_time: None,
                            }),
                        },
                    );
                }

                instance_answers_monitor(&local_db, &btc_client, &goat_client)
                    .await
                    .unwrap();

                let mut storage = local_db.acquire().await.unwrap();
                let (instances, _) = storage
                    .find_instances(InstanceQuery::default().with_is_bridge_in(true))
                    .await
                    .unwrap();
                if outside_window {
                    let instance = instances.into_iter().next().unwrap();
                    assert_eq!(instance.status, InstanceBridgeInStatus::UserDiscarded.to_string());
                } else {
                    let msg = storage
                        .find_message_by_business_id(&instance_id, &MessageType::PeginRequest.to_string())
                        .await
                        .unwrap();
                    assert!(msg.is_some());
                }
            });
            Ok(())
        })
        .unwrap();
}
