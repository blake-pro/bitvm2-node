use axum::Json;
use axum::extract::State;
use bitvm2_lib::actors::Actor;
use bitvm2_noded::rpc_service::AppState;
use bitvm2_noded::rpc_service::handler::{bridge_in_request_tag, bridge_out_init_tag};
use bitvm2_noded::rpc_service::{BridgeInPrepareRequest, BridgeOutInitTagRequest};
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::http_client::async_client::HttpAsyncClient;
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
use serial_test::serial;
use std::env;
use std::sync::{Arc, Mutex};
use store::{InstanceBridgeInStatus, InstanceBridgeOutStatus};
use store::create_local_db;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

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

async fn build_state(temp_db: &NamedTempFile) -> Arc<AppState> {
    let local_db = create_local_db(&format!("sqlite:{}", temp_db.path().display())).await;
    let (btc_client, _btc_mock) = BTCClient::new_mock_client();
    let (goat_client, _goat_mock) = GOATClient::new_mock_client();
    let metrics_state = bitvm2_noded::metrics_service::MetricsState::new(Arc::new(Mutex::new(
        prometheus_client::registry::Registry::default(),
    )));
    Arc::new(AppState {
        local_db,
        btc_client,
        goat_client,
        metrics_state,
        actor: Actor::Operator,
        peer_id: "test".to_string(),
        http_client: HttpAsyncClient::new(None),
    })
}

#[test]
#[serial]
fn prop_bridge_in_request_tag_creates_instance() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(1u8), Just(2u8)];

    runner
        .run(&strat, |_| {
            run_async(async move {
                setup_env();
                let temp_db = NamedTempFile::new().unwrap();
                let app_state = build_state(&temp_db).await;

                let payload = BridgeInPrepareRequest {
                    instance_id: uuid::Uuid::new_v4().to_string(),
                    contract_address: "0x0000000000000000000000000000000000000000".to_string(),
                    from_addr: test_support::valid_btc_address(),
                    to_addr: "0x0000000000000000000000000000000000000001".to_string(),
                    bridge_request_tx_hash: "0xbridge_req".to_string(),
                };
                let _ = bridge_in_request_tag(
                    State(app_state.clone()),
                    Json(payload),
                )
                .await
                .unwrap();

                let mut storage = app_state.local_db.acquire().await.unwrap();
                let instances = storage
                    .find_instances(store::localdb::InstanceQuery::default().with_is_bridge_in(true))
                    .await
                    .unwrap()
                    .0;
                assert_eq!(instances.len(), 1);
                assert_eq!(
                    instances[0].status,
                    InstanceBridgeInStatus::UserIniting.to_string()
                );
            });
            Ok(())
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_bridge_out_init_tag_creates_instance() {
    let mut runner = build_test_runner();
    let strat = prop_oneof![Just(true), Just(false)];

    runner
        .run(&strat, |_| {
            run_async(async move {
                setup_env();
                let temp_db = NamedTempFile::new().unwrap();
                let app_state = build_state(&temp_db).await;

                let payload = BridgeOutInitTagRequest {
                    contract_address: "0x0000000000000000000000000000000000000000".to_string(),
                    from_addr: "0x0000000000000000000000000000000000000001".to_string(),
                    to_addr: test_support::valid_btc_address(),
                    escrow_hash: format!("0x{}", "11".repeat(32)),
                };
                let _ = bridge_out_init_tag(
                    State(app_state.clone()),
                    Json(payload),
                )
                .await
                .unwrap();

                let mut storage = app_state.local_db.acquire().await.unwrap();
                let instances = storage
                    .find_instances(store::localdb::InstanceQuery::default().with_is_bridge_in(false))
                    .await
                    .unwrap()
                    .0;
                assert_eq!(instances.len(), 1);
                assert_eq!(
                    instances[0].status,
                    InstanceBridgeOutStatus::Initialize.to_string()
                );
            });
            Ok(())
        })
        .unwrap();
}
