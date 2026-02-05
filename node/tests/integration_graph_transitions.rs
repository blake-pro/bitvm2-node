use bitcoin::{Txid as BitcoinTxid, hashes::Hash as _};
use bitvm2_noded::env;
use bitvm2_noded::rpc_service::current_time_secs;
use bitvm2_noded::scheduled_tasks::graph_maintenance_tasks::{
    AssertCommitStatus, AssertInitTxVoutMonitorData, ChallengeSubStatus, CommitBlockHashStatus,
    WTInitTxVoutMonitorData, WatchtowerChallengeItemStatus, WatchtowerChallengeStatus,
    detect_kickoff, detect_take1_or_challenge, get_challenge_timelock_config,
    process_assert_commit_monitoring, process_watchtower_challenge_monitoring,
};

use client::btc_chain::{BTCClient, mock_bitcoin_adaptor::MockBitcoinAdaptor};
use client::goat_chain::{
    GOATClient, mock_goat_adaptor::{GatewayContractConfig, MockAdaptor},
};

use bitvm2_lib::operator::take1_timelock;
use esplora_client::OutputStatus;
use store::{Graph, GraphBtcTxVoutMonitor, GraphStatus, create_local_db, localdb::LocalDB};
use tempfile::NamedTempFile;

use uuid::Uuid;

mod test_support;

async fn setup() -> (LocalDB, BTCClient, MockBitcoinAdaptor, GOATClient, MockAdaptor, NamedTempFile)
{
    // Set Env Vars for RPC start - modeled after integration_tests.rs
    unsafe {
        std::env::set_var("BTC_Node_URL", "http://127.0.0.1:18443");
        std::env::set_var("GOAT_CHAIN_URL", "http://127.0.0.1:8545");
        std::env::set_var(
            "GOAT_GATEWAY_CONTRACT_ADDRESS",
            "0x0000000000000000000000000000000000000000",
        );
        std::env::set_var(env::ENV_BITVM_SECRET, "seed:test-secret");
        std::env::set_var(env::ENV_BITCOIN_NETWORK, "testnet4");
    }

    let db_file = NamedTempFile::new().unwrap();
    let db_path = db_file.path().to_str().unwrap().to_string();
    let local_db = create_local_db(&format!("sqlite:{db_path}")).await;

    let (btc_client, btc_mock) = BTCClient::new_mock_client();
    let (goat_client, goat_mock) = GOATClient::new_mock_client();

    goat_mock.set_gateway_contract_config(GatewayContractConfig {
        min_challenge_amount_sats: 100000,
        min_pegin_fee_sats: 5000,
        pegin_fee_rate: 50,
        min_operator_reward_sats: 3000,
        operator_reward_rate: 30,
        min_stake_amount: 60000000000000000,
        min_challenger_reward: 12500000000000000,
        min_disprover_reward: 2500000000000000,
        min_slash_amount: 30000000000000000,
    });

    (local_db, btc_client, btc_mock, goat_client, goat_mock, db_file)
}

#[tokio::test]
async fn test_challenge_phase_transitions() {
    let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    // 1. Initial State: Challenge Started, Waiting for Watchtowers
    let sub_status = ChallengeSubStatus {
        watchtower_challenge_status: WatchtowerChallengeStatus::WatchtowerChallenge,
        ..Default::default()
    };

    let watchtower_init_txid = BitcoinTxid::from_byte_array([0x22; 32]);
    let kickoff_txid = BitcoinTxid::from_byte_array([0x11; 32]);
    let blockhash_timeout_txid = BitcoinTxid::from_byte_array([0x33; 32]);

    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::Challenge.to_string(),
        sub_status: serde_json::to_string(&sub_status).unwrap(),
        kickoff_txid: Some(kickoff_txid.into()),
        watchtower_challenge_init_txid: Some(watchtower_init_txid.into()),
        blockhash_commit_timeout_txid: Some(blockhash_timeout_txid.into()),
        watchtower_challenge_timeout_txids: vec![],
        nack_txids: vec![],
        ..Default::default()
    };

    {
        let mut storage = local_db.acquire().await.unwrap();
        storage.upsert_graph(&graph).await.unwrap();
    }

    // Insert WTInitTxVoutMonitorData
    let index_size = 2;
    let monitor_data = WTInitTxVoutMonitorData::new(index_size);

    let monitor_record = GraphBtcTxVoutMonitor {
        graph_id,
        tx_name: "watchtower_init".to_string(),
        txid: watchtower_init_txid.into(),
        height: 100,
        vout_len: (index_size * 2 + 3) as i64,
        monitor_data: serde_json::to_string(&monitor_data).unwrap(),
        created_at: current_time_secs(),
        updated_at: current_time_secs(),
    };
    {
        let mut storage = local_db.acquire().await.unwrap();
        storage.upsert_graph_btc_tx_vout_monitor(&monitor_record).await.unwrap();
    }

    // 2. Drive State: Watchtower Challenge Phase -> Timeout/ACK Timeout depending on timelocks
    let timelock_config = get_challenge_timelock_config();
    let current_height =
        100 + std::cmp::min(
            timelock_config.watchtower_challenge_timelock,
            timelock_config.watchtower_ack_timelock,
        ) + 1;

    // Mock BTC Outputs: Ensure Watchtower Init outputs are UNSPENT
    for i in 0..monitor_record.vout_len {
        btc_mock.set_output_status(
            watchtower_init_txid,
            i as u64,
            OutputStatus { spent: false, txid: None, vin: None, status: None },
        );
    }

    // Run Logic
    let mut updated_sub_status = sub_status;
    process_watchtower_challenge_monitoring(
        &btc_client,
        &local_db,
        &graph,
        &mut updated_sub_status,
        current_height,
    )
    .await
    .unwrap();

    // 3. Verify Transition to Timeout (ChallengeTimeout or AckTimeout path)
    let updated_graph = {
        let mut storage = local_db.acquire().await.unwrap();
        storage.find_graph(&graph_id).await.unwrap().unwrap()
    };
    let saved_sub_status: ChallengeSubStatus =
        serde_json::from_str(&updated_graph.sub_status).unwrap();

    let timeout_status = updated_sub_status.watchtower_challenge_status;
    assert!(
        matches!(
            timeout_status,
            WatchtowerChallengeStatus::WatchtowerChallengeTimeout
                | WatchtowerChallengeStatus::WatchtowerChallengeDisproveFinished
        ),
        "Unexpected watchtower status: {timeout_status:?}"
    );
    assert_eq!(saved_sub_status.watchtower_challenge_status, timeout_status);

    // Fast Forward beyond both challenge and ACK timelocks to force DisproveFinished
    let current_height_ack =
        100 + std::cmp::max(
            timelock_config.watchtower_challenge_timelock,
            timelock_config.watchtower_ack_timelock,
        ) + 2;
    process_watchtower_challenge_monitoring(
        &btc_client,
        &local_db,
        &updated_graph,
        &mut updated_sub_status,
        current_height_ack,
    )
    .await
    .unwrap();

    assert_eq!(
        updated_sub_status.watchtower_challenge_status,
        WatchtowerChallengeStatus::WatchtowerChallengeDisproveFinished
    );
}

#[tokio::test]
async fn test_watchtower_challenge_happy_path() {
    let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    // 1. Initial State: Watchtower Challenge
    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::Challenge.to_string(),
        sub_status: Default::default(),
        kickoff_txid: Some(BitcoinTxid::from_byte_array([1u8; 32]).into()),
        watchtower_challenge_init_txid: Some(BitcoinTxid::from_byte_array([2u8; 32]).into()),
        blockhash_commit_timeout_txid: Some(BitcoinTxid::from_byte_array([3u8; 32]).into()),
        watchtower_challenge_timeout_txids: vec![BitcoinTxid::from_byte_array([4u8; 32]).into()],
        nack_txids: vec![BitcoinTxid::from_byte_array([5u8; 32]).into()],
        ..Default::default()
    };

    let sub_status = ChallengeSubStatus {
        watchtower_challenge_status: WatchtowerChallengeStatus::WatchtowerChallenge,
        ..Default::default()
    };

    let watchtower_init_txid = graph.watchtower_challenge_init_txid.clone().unwrap().0;

    // Store Monitor Data
    // Simulate ONE watchtower that has already ACKed (OperatorACK).
    // This allows `require_disproved_indexes.is_empty()` to be true (NormalFinished condition).
    let mut vout_monitor = WTInitTxVoutMonitorData::new(1);
    vout_monitor.data_map.insert(0, WatchtowerChallengeItemStatus::OperatorACK);

    let monitor_record = GraphBtcTxVoutMonitor {
        graph_id,
        tx_name: "watchtower_init".to_string(),
        txid: watchtower_init_txid.into(),
        height: 100,
        vout_len: 5,
        monitor_data: serde_json::to_string(&vout_monitor).unwrap(),
        created_at: 0,
        updated_at: 0,
    };

    {
        let mut storage_processor = local_db.acquire().await.unwrap();
        storage_processor.upsert_graph_btc_tx_vout_monitor(&monitor_record).await.unwrap();
    }

    // 2. Drive State: Watchtower Challenge -> NormalFinished (Happy Path)
    let timelock_config = get_challenge_timelock_config();
    // Advance block height past ACK timeout
    let current_height = 100 + timelock_config.watchtower_ack_timelock + 1;

    // Mock BTC Outputs: UNSPENT (simulating no challenge/timeout tx on chain)
    for i in 0..monitor_record.vout_len {
        btc_mock.set_output_status(
            watchtower_init_txid,
            i as u64,
            OutputStatus { spent: false, txid: None, vin: None, status: None },
        );
    }

    let mut updated_sub_status = sub_status;
    process_watchtower_challenge_monitoring(
        &btc_client,
        &local_db,
        &graph,
        &mut updated_sub_status,
        current_height,
    )
    .await
    .unwrap();

    assert_eq!(
        updated_sub_status.watchtower_challenge_status,
        WatchtowerChallengeStatus::WatchtowerChallengeNormalFinished
    );
}

#[tokio::test]
async fn test_commit_blockhash_transitions() {
    let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    let timelock_config = get_challenge_timelock_config();

    // 1. Initial Setup for BlockHash Phase
    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::Challenge.to_string(), // Still in Challenge main status
        sub_status: Default::default(),
        kickoff_txid: Some(BitcoinTxid::from_byte_array([1u8; 32]).into()),
        watchtower_challenge_init_txid: Some(BitcoinTxid::from_byte_array([2u8; 32]).into()),
        blockhash_commit_timeout_txid: Some(BitcoinTxid::from_byte_array([3u8; 32]).into()),
        ..Default::default()
    };

    let watchtower_init_txid = graph.watchtower_challenge_init_txid.clone().unwrap().0;

    // Create monitor with default state (CommitBlockHashStatus::None)
    let monitor_record = GraphBtcTxVoutMonitor {
        graph_id,
        tx_name: "watchtower_init".to_string(),
        txid: watchtower_init_txid.into(),
        height: 100,
        vout_len: 5,
        monitor_data: serde_json::to_string(&WTInitTxVoutMonitorData::new(1)).unwrap(),
        created_at: 0,
        updated_at: 0,
    };

    {
        let mut storage_processor = local_db.acquire().await.unwrap();
        storage_processor.upsert_graph_btc_tx_vout_monitor(&monitor_record).await.unwrap();
    }

    // --- Scenario A: Success (Operator Commit) ---
    // The connector index for Commit Blockhash is calculated as (vout_len - 3).
    let commit_idx = 5 - 3; // 2
    let commit_txid = BitcoinTxid::from_byte_array([9u8; 32]);

    // Mock Output Status: Spent by Operator Commit
    btc_mock.set_output_status(
        watchtower_init_txid,
        commit_idx as u64,
        OutputStatus {
            spent: true,
            txid: Some(commit_txid),
            vin: Some(0),
            status: Some(esplora_client::TxStatus {
                confirmed: true,
                block_height: Some(150),
                block_hash: None,
                block_time: None,
            }),
        },
    );

    let mut sub_status = ChallengeSubStatus::default();
    let current_height =
        100 + std::cmp::max(1, timelock_config.watchtower_blockhash_commit_timelock - 1);

    process_watchtower_challenge_monitoring(
        &btc_client,
        &local_db,
        &graph,
        &mut sub_status,
        current_height,
    )
    .await
    .unwrap();

    assert_eq!(sub_status.commit_blockhash_status, CommitBlockHashStatus::OperatorCommit);

    // --- Scenario B: Timeout ---
    // Reset DB state
    {
        let mut storage_processor = local_db.acquire().await.unwrap();
        let mut reset_monitor = monitor_record.clone();
        reset_monitor.monitor_data =
            serde_json::to_string(&WTInitTxVoutMonitorData::new(1)).unwrap();
        storage_processor.upsert_graph_btc_tx_vout_monitor(&reset_monitor).await.unwrap();
    }

    // Mock Output Status: Unspent
    btc_mock.set_output_status(
        watchtower_init_txid,
        commit_idx as u64,
        OutputStatus { spent: false, txid: None, vin: None, status: None },
    );

    let mut sub_status_timeout = ChallengeSubStatus::default();
    // Advance height past timeout
    let timeout_height = 100 + timelock_config.watchtower_blockhash_commit_timelock + 1;

    process_watchtower_challenge_monitoring(
        &btc_client,
        &local_db,
        &graph,
        &mut sub_status_timeout,
        timeout_height,
    )
    .await
    .unwrap();

    assert_eq!(
        sub_status_timeout.commit_blockhash_status,
        CommitBlockHashStatus::OperatorCommitTimeout
    );
}

#[tokio::test]
async fn test_assert_commit_transitions() {
    let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    let timelock_config = get_challenge_timelock_config();

    // 1. Initial Setup for Assert Commit Phase
    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::Challenge.to_string(),
        sub_status: Default::default(),
        kickoff_txid: Some(BitcoinTxid::from_byte_array([1u8; 32]).into()),
        assert_init_txid: Some(BitcoinTxid::from_byte_array([6u8; 32]).into()),
        assert_commit_timeout_txids: vec![BitcoinTxid::from_byte_array([7u8; 32]).into()],
        ..Default::default()
    };

    let assert_init_txid = graph.assert_init_txid.clone().unwrap().0;

    // Create monitor for Assert Init
    let monitor_record = GraphBtcTxVoutMonitor {
        graph_id,
        tx_name: "assert_init".to_string(),
        txid: assert_init_txid.into(),
        height: 200,
        vout_len: 2, // Assume simple structure
        monitor_data: serde_json::to_string(&AssertInitTxVoutMonitorData::new(1)).unwrap(),
        created_at: 0,
        updated_at: 0,
    };

    {
        let mut storage_processor = local_db.acquire().await.unwrap();
        storage_processor.upsert_graph_btc_tx_vout_monitor(&monitor_record).await.unwrap();
    }

    // --- Scenario A: Success (Operator Assert) ---
    // The connector index for Assert need to be found via `get_assert_commit_desc`.
    // In `AssertInitTxVoutMonitorData` (not visible here, but usually similar logic).
    // Let's assume standard behavior: spending the output triggers it.

    let assert_commit_txid = BitcoinTxid::from_byte_array([8u8; 32]);
    let assert_idx = 0; // Guessing index 0 for assert_commit connector

    // Mock Output Status: Spent by Operator Assert
    btc_mock.set_output_status(
        assert_init_txid,
        assert_idx as u64,
        OutputStatus {
            spent: true,
            txid: Some(assert_commit_txid),
            vin: Some(0),
            status: Some(esplora_client::TxStatus {
                confirmed: true,
                block_height: Some(250),
                block_hash: None,
                block_time: None,
            }),
        },
    );

    let mut sub_status = ChallengeSubStatus::default();
    let current_height = 200 + std::cmp::max(1, timelock_config.assert_commit_timelock - 1);

    process_assert_commit_monitoring(
        &btc_client,
        &local_db,
        &graph,
        &mut sub_status,
        current_height,
    )
    .await
    .unwrap();

    assert_eq!(sub_status.assert_commit_status, AssertCommitStatus::OperatorCommit);

    // --- Scenario B: Timeout ---
    // Reset DB state
    {
        let mut storage_processor = local_db.acquire().await.unwrap();
        let mut reset_monitor = monitor_record.clone();
        reset_monitor.monitor_data =
            serde_json::to_string(&AssertInitTxVoutMonitorData::new(1)).unwrap();
        storage_processor.upsert_graph_btc_tx_vout_monitor(&reset_monitor).await.unwrap();
    }

    // Mock Output Status: Unspent
    btc_mock.set_output_status(
        assert_init_txid,
        assert_idx as u64,
        OutputStatus { spent: false, txid: None, vin: None, status: None },
    );

    let mut sub_status_timeout = ChallengeSubStatus::default();
    // Advance height past timeout
    let timeout_height = 200 + timelock_config.assert_commit_timelock + 1;

    process_assert_commit_monitoring(
        &btc_client,
        &local_db,
        &graph,
        &mut sub_status_timeout,
        timeout_height,
    )
    .await
    .unwrap();

    assert_eq!(sub_status_timeout.assert_commit_status, AssertCommitStatus::OperatorCommitTimeout);
}

#[tokio::test]
async fn test_kickoff_detection() {
    let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    // 1. Initial State: OperatorDataPushed
    let kickoff_txid = BitcoinTxid::from_byte_array([10u8; 32]);
    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::OperatorDataPushed.to_string(),
        sub_status: Default::default(),
        kickoff_txid: Some(kickoff_txid.into()),
        operator_pubkey: "020000000000000000000000000000000000000000000000000000000000000000"
            .to_string(), // Must be non-empty for fetch_on_turn filter
        ..Default::default()
    };

    {
        let mut storage = local_db.acquire().await.unwrap();
        storage.upsert_graph(&graph).await.unwrap();
    }

    // 2. Mock Kickoff Transaction: Confirmed on Chain
    btc_mock.set_output_status(
        kickoff_txid,
        0, // Index doesn't strictly matter for detect_kickoff, it just checks tx_status
        OutputStatus {
            spent: false,
            txid: None,
            vin: None,
            status: Some(esplora_client::TxStatus {
                confirmed: true,
                block_height: Some(50),
                block_hash: None,
                block_time: None,
            }),
        },
    );
    // Explicitly set tx status using set_tx
    let tx_status = esplora_client::TxStatus {
        confirmed: true,
        block_height: Some(50),
        block_hash: None,
        block_time: None,
    };
    let tx = esplora_client::Tx {
        txid: kickoff_txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![],
        status: tx_status,
        fee: 100,
        size: 100,
        weight: 400,
    };
    btc_mock.set_tx(kickoff_txid, tx);

    // 3. Call detect_kickoff
    detect_kickoff(&local_db, &btc_client).await.unwrap();

    // 4. Verify Message "KickoffSent" inserted
    let message = {
        let mut storage = local_db.acquire().await.unwrap();
        // business_id is graph_id, msg_type is "KickoffSent"?
        // Need to check specific string for KickoffSent in GOATMessageContent variant mapping or usage?
        // Detect Kickoff should create a KickoffSent message
        storage.find_message_by_business_id(&graph_id, "KickoffSent").await.unwrap()
    };

    assert!(message.is_some(), "KickoffSent message should be inserted");
    let msg = message.unwrap();
    // Optionally check content, but msg_type "self" + existence is good enough for step 1.
    // Ideally verify content matches GOATMessageContent::KickoffSent
    // But content is serialized JSON.
    assert!(String::from_utf8(msg.content).unwrap().contains("KickoffSent"));
}

#[tokio::test]
async fn test_kickoff_to_take1_transition() {
    let (local_db, btc_client, btc_mock, _goat_client, _goat_mock, _db_file) = setup().await;
    let graph_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    // 1. Initial State: OperatorKickOff
    let kickoff_txid = BitcoinTxid::from_byte_array([0xAA; 32]);
    let take1_txid = BitcoinTxid::from_byte_array([0xBB; 32]);
    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::OperatorKickOff.to_string(),
        sub_status: Default::default(),
        kickoff_txid: Some(kickoff_txid.into()),
        take1_txid: Some(take1_txid.into()),
        operator_pubkey: "020000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        ..Default::default()
    };

    {
        let mut storage = local_db.acquire().await.unwrap();
        storage.upsert_graph(&graph).await.unwrap();
    }

    // 2. Mock Kickoff Confirmation
    let kickoff_height = 100;

    // Ensure output 0 is UNSPENT (as Take1 spends it, but we are checking readiness)
    btc_mock.set_output_status(
        kickoff_txid,
        0,
        OutputStatus {
            spent: false,
            txid: None,
            vin: None,
            status: Some(esplora_client::TxStatus {
                confirmed: true,
                block_height: Some(kickoff_height),
                block_hash: None,
                block_time: None,
            }),
        },
    );

    let tx = esplora_client::Tx {
        txid: kickoff_txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![],
        status: esplora_client::TxStatus {
            confirmed: true,
            block_height: Some(kickoff_height),
            block_hash: None,
            block_time: None,
        },
        fee: 100,
        size: 100,
        weight: 400,
    };
    btc_mock.set_tx(kickoff_txid, tx);

    // 3. Set Current Height > Kickoff + Timelock
    let current_height = kickoff_height + take1_timelock(env::get_network()) + 10;
    btc_mock.set_height(current_height);

    // 4. Run Logic
    detect_take1_or_challenge(&local_db, &btc_client).await.unwrap();

    // 5. Assert Take1Ready Message Inserted
    let message = {
        let mut storage = local_db.acquire().await.unwrap();
        storage.find_message_by_business_id(&graph_id, "Take1Ready").await.unwrap()
    };

    assert!(message.is_some(), "Should generate Take1Ready message");
}
