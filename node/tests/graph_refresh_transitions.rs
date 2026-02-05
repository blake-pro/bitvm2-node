use alloy::primitives::U256;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Network, OutPoint, PublicKey, Txid as BitcoinTxid};
use bitvm2_lib::keys::OperatorMasterKey;
use bitvm2_lib::operator::generate_bitvm_graph;
use bitvm2_lib::types::{
    Bitvm2GraphParameters, Bitvm2InstanceParameters, PrekickoffParameters, SimplifiedBitvm2Graph,
    UserInfo,
};
use bitvm2_noded::env;
use bitvm2_noded::utils::{refresh_graph, store_graph, todo_funcs, update_graph_status};
use client::btc_chain::{BTCClient, mock_bitcoin_adaptor::MockBitcoinAdaptor};
use client::goat_chain::{
    GOATClient, GraphData, PeginData, PeginStatus, Utxo as GoatUtxo, WithdrawData, WithdrawStatus,
    mock_goat_adaptor::MockAdaptor,
};
use esplora_client::{Tx, TxStatus, Vout};
use goat::connectors::kickoff_connectors::{
    ForceSkipConnector, KickoffConnector, PrekickoffConnector,
};
use goat::contexts::base::generate_n_of_n_public_key;
use goat::disprove_scripts::hash160;
use goat::scripts::p2a_script;
use goat::transactions::base::Input;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::prekickoff::PrekickoffTransaction;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serial_test::serial;
use store::localdb::{GraphUpdate, LocalDB};
use store::{Graph, GraphStatus, Instance, InstanceBridgeInStatus, UInt64Array3, create_local_db};
use tempfile::NamedTempFile;
use uuid::Uuid;
use zkm_sdk::ZKM_CIRCUIT_VERSION;

const PREKICKOFF_KICKOFF_VOUT: u64 = 1;
const KICKOFF_TAKE2_VOUT: u64 = 3;

struct TestEnvGuard {
    bitvm_secret: Option<String>,
    bitcoin_network: Option<String>,
}

impl TestEnvGuard {
    fn new() -> Self {
        let bitvm_secret = std::env::var(env::ENV_BITVM_SECRET).ok();
        let bitcoin_network = std::env::var(env::ENV_BITCOIN_NETWORK).ok();
        unsafe {
            std::env::set_var(env::ENV_BITVM_SECRET, "seed:test-secret");
            std::env::set_var(env::ENV_BITCOIN_NETWORK, "regtest");
        }
        Self { bitvm_secret, bitcoin_network }
    }
}

impl Drop for TestEnvGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(value) = self.bitvm_secret.as_ref() {
                std::env::set_var(env::ENV_BITVM_SECRET, value);
            } else {
                std::env::remove_var(env::ENV_BITVM_SECRET);
            }
            if let Some(value) = self.bitcoin_network.as_ref() {
                std::env::set_var(env::ENV_BITCOIN_NETWORK, value);
            } else {
                std::env::remove_var(env::ENV_BITCOIN_NETWORK);
            }
        }
    }
}

fn test_keypair_from_byte(byte: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
    Keypair::from_secret_key(&secp, &secret_key)
}

fn test_xonly_pubkey() -> [u8; 32] {
    let keypair = test_keypair_from_byte(11);
    let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    xonly_pubkey.serialize()
}

fn test_address(network: Network) -> bitcoin::Address {
    let keypair = test_keypair_from_byte(12);
    let public_key: PublicKey = keypair.public_key().into();
    bitcoin::Address::p2pkh(public_key, network)
}

fn build_test_instance_parameters(instance_id: Uuid) -> Bitvm2InstanceParameters {
    let network = env::get_network();
    let user_change_address = test_address(network);
    let user_refund_address = test_address(network);
    let user_xonly_pubkey = XOnlyPublicKey::from_keypair(&test_keypair_from_byte(4)).0;
    let inputs = vec![Input {
        outpoint: OutPoint { txid: BitcoinTxid::from_byte_array([9u8; 32]), vout: 0 },
        amount: Amount::from_sat(200000),
    }];
    let user_info = UserInfo {
        depositor_evm_address: [0u8; 20],
        txn_fees: [100, 100, 100],
        inputs,
        user_change_address,
        user_refund_address,
        user_xonly_pubkey,
    };
    let committee_pubkeys: Vec<PublicKey> = vec![
        test_keypair_from_byte(5).public_key().into(),
        test_keypair_from_byte(6).public_key().into(),
    ];
    let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    Bitvm2InstanceParameters {
        network,
        instance_id,
        user_info,
        pegin_amount: Amount::from_sat(100000),
        committee_pubkeys,
        committee_agg_pubkey,
    }
}

fn build_test_prekickoff_parameters(
    operator_taproot_public_key: XOnlyPublicKey,
) -> PrekickoffParameters {
    let network = env::get_network();
    let prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    let kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let input = Input {
        outpoint: OutPoint { txid: BitcoinTxid::from_byte_array([10u8; 32]), vout: 0 },
        amount: Amount::from_sat(200000),
    };
    let cur_prekickoff_txn = PrekickoffTransaction::new_for_validation(
        &prekickoff_connector,
        &force_skip_connector,
        &kickoff_connector,
        &prekickoff_connector,
        input,
        vec![],
        vec![],
        1000,
        1,
        todo_funcs::assert_commmit_num(),
    )
    .unwrap();
    PrekickoffParameters {
        cur_prekickoff_txn,
        replenish_fee_inputs: vec![],
        replenish_fee_prev_outs: vec![],
        fee_amount: 1000,
    }
}

fn build_test_simplified_graph(instance_id: Uuid) -> SimplifiedBitvm2Graph {
    let operator_master_key = OperatorMasterKey::new(env::get_bitvm_key().unwrap());
    let operator_keypair = operator_master_key.master_keypair();
    let operator_pubkey: PublicKey = operator_keypair.public_key().into();
    let operator_taproot_public_key = operator_keypair.x_only_public_key().0;
    let graph_id = Uuid::new_v4();
    let instance_parameters = build_test_instance_parameters(instance_id);
    let prekickoff_parameters = build_test_prekickoff_parameters(operator_taproot_public_key);
    let operator_wots_pubkeys = operator_master_key.wots_keypair_for_graph(graph_id).1;
    let watchtower_pubkeys = vec![test_keypair_from_byte(7).public_key().x_only_public_key().0];
    let hashlocks =
        watchtower_pubkeys.iter().map(|_| hash160(&b"preimage".to_vec())).collect::<Vec<_>>();
    let graph_params = Bitvm2GraphParameters {
        instance_parameters,
        prekickoff_parameters,
        graph_id,
        graph_nonce: 1,
        challenge_amount: todo_funcs::challenge_amount(),
        operator_pubkey,
        operator_wots_pubkeys,
        operator_receive_address: test_address(env::get_network()),
        watchtower_pubkeys,
        hashlocks,
        guest_constant_value: [3u8; 32],
        zkm_version: ZKM_CIRCUIT_VERSION.to_string(),
    };
    let disprove_scripts = vec![p2a_script()];
    let graph = generate_bitvm_graph(graph_params, disprove_scripts).unwrap();
    graph.to_simplified().unwrap()
}

async fn setup_db()
-> (LocalDB, BTCClient, MockBitcoinAdaptor, GOATClient, MockAdaptor, NamedTempFile) {
    let db_file = NamedTempFile::new().unwrap();
    let local_db = create_local_db(&format!("sqlite:{}", db_file.path().display())).await;
    let (btc_client, btc_mock) = BTCClient::new_mock_client();
    let (goat_client, goat_mock) = GOATClient::new_mock_client();
    (local_db, btc_client, btc_mock, goat_client, goat_mock, db_file)
}

async fn set_graph_status(local_db: &LocalDB, graph_id: Uuid, status: GraphStatus) {
    let mut storage = local_db.acquire().await.unwrap();
    storage
        .update_graph(&GraphUpdate::new(graph_id).with_status(status.to_string()))
        .await
        .unwrap();
}

#[tokio::test]
#[serial]
async fn refresh_graph_operator_data_pushed_to_prekickoff() {
    let _env_guard = TestEnvGuard::new();
    let (local_db, btc_client, btc_mock, goat_client, goat_mock, _db_file) = setup_db().await;
    let instance_id = Uuid::new_v4();
    let simplified_graph = build_test_simplified_graph(instance_id);
    store_graph(&local_db, &simplified_graph).await.unwrap();
    let graph_id = simplified_graph.parameters.graph_id;

    let full_graph = bitvm2_lib::types::Bitvm2Graph::from_simplified(&simplified_graph).unwrap();
    let prekickoff_txid = full_graph.cur_prekickoff.tx().compute_txid();

    let tx = Tx {
        txid: prekickoff_txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![Vout {
            scriptpubkey: test_address(env::get_network()).script_pubkey(),
            value: 1000,
        }],
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
    btc_mock.set_tx(prekickoff_txid, tx);

    let network = env::get_network();
    let user_change_address = test_address(network);
    let user_refund_address = user_change_address.clone();
    let pegin_data = PeginData {
        status: PeginStatus::Withdrawable,
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats: 100000,
        txn_fees: [100, 100, 100],
        user_inputs: vec![GoatUtxo { txid: [9u8; 32], vout: 0, amount_sats: 200000 }],
        user_xonly_pubkey: test_xonly_pubkey(),
        user_change_addr: user_change_address.to_string(),
        user_refund_addr: user_refund_address.to_string(),
        pegin_txid: [3u8; 32],
        created_at: 0,
        committee_addresses: vec![],
        committee_pubkeys: vec![],
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);
    let withdraw_data = WithdrawData {
        pegin_txid: [3u8; 32],
        operator_address: [0u8; 20],
        status: WithdrawStatus::None,
        instance_id: *instance_id.as_bytes(),
        lock_amount: U256::ZERO,
        btc_block_height_withdraw: U256::ZERO,
    };
    goat_mock.set_withdraw_data(*graph_id.as_bytes(), withdraw_data);

    set_graph_status(&local_db, graph_id, GraphStatus::OperatorDataPushed).await;
    let (status, _) = refresh_graph(
        &local_db,
        &btc_client,
        &goat_client,
        instance_id,
        graph_id,
        None,
        Some(GraphStatus::OperatorDataPushed),
        None,
    )
    .await
    .unwrap();

    assert_eq!(status, GraphStatus::PreKickoff);
    let mut storage = local_db.acquire().await.unwrap();
    let updated = storage.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated.status, GraphStatus::PreKickoff.to_string());
}

#[tokio::test]
#[serial]
async fn refresh_graph_prekickoff_to_kickoff() {
    let _env_guard = TestEnvGuard::new();
    let (local_db, btc_client, btc_mock, goat_client, _goat_mock, _db_file) = setup_db().await;
    let instance_id = Uuid::new_v4();
    let simplified_graph = build_test_simplified_graph(instance_id);
    store_graph(&local_db, &simplified_graph).await.unwrap();
    let graph_id = simplified_graph.parameters.graph_id;

    let full_graph = bitvm2_lib::types::Bitvm2Graph::from_simplified(&simplified_graph).unwrap();
    let prekickoff_txid = full_graph.cur_prekickoff.tx().compute_txid();
    let kickoff_txid = full_graph.kickoff.tx().compute_txid();

    let tx = Tx {
        txid: prekickoff_txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![Vout {
            scriptpubkey: test_address(env::get_network()).script_pubkey(),
            value: 1000,
        }],
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
    btc_mock.set_tx(prekickoff_txid, tx);

    btc_mock.set_output_status(
        prekickoff_txid,
        PREKICKOFF_KICKOFF_VOUT,
        esplora_client::OutputStatus {
            spent: true,
            txid: Some(kickoff_txid),
            vin: Some(0),
            status: Some(TxStatus {
                confirmed: true,
                block_height: Some(11),
                block_hash: None,
                block_time: None,
            }),
        },
    );

    set_graph_status(&local_db, graph_id, GraphStatus::PreKickoff).await;
    let (status, _) = refresh_graph(
        &local_db,
        &btc_client,
        &goat_client,
        instance_id,
        graph_id,
        None,
        Some(GraphStatus::PreKickoff),
        None,
    )
    .await
    .unwrap();

    assert_eq!(status, GraphStatus::OperatorKickOff);
    let mut storage = local_db.acquire().await.unwrap();
    let updated = storage.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated.status, GraphStatus::OperatorKickOff.to_string());
}

#[tokio::test]
#[serial]
async fn refresh_graph_prekickoff_to_skipped() {
    let _env_guard = TestEnvGuard::new();
    let (local_db, btc_client, btc_mock, goat_client, _goat_mock, _db_file) = setup_db().await;
    let instance_id = Uuid::new_v4();
    let simplified_graph = build_test_simplified_graph(instance_id);
    store_graph(&local_db, &simplified_graph).await.unwrap();
    let graph_id = simplified_graph.parameters.graph_id;

    let full_graph = bitvm2_lib::types::Bitvm2Graph::from_simplified(&simplified_graph).unwrap();
    let prekickoff_txid = full_graph.cur_prekickoff.tx().compute_txid();
    let other_txid = BitcoinTxid::from_byte_array([7u8; 32]);

    let tx = Tx {
        txid: prekickoff_txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![Vout {
            scriptpubkey: test_address(env::get_network()).script_pubkey(),
            value: 1000,
        }],
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
    btc_mock.set_tx(prekickoff_txid, tx);

    btc_mock.set_output_status(
        prekickoff_txid,
        PREKICKOFF_KICKOFF_VOUT,
        esplora_client::OutputStatus {
            spent: true,
            txid: Some(other_txid),
            vin: Some(0),
            status: Some(TxStatus {
                confirmed: true,
                block_height: Some(11),
                block_hash: None,
                block_time: None,
            }),
        },
    );

    set_graph_status(&local_db, graph_id, GraphStatus::PreKickoff).await;
    let (status, _) = refresh_graph(
        &local_db,
        &btc_client,
        &goat_client,
        instance_id,
        graph_id,
        None,
        Some(GraphStatus::PreKickoff),
        None,
    )
    .await
    .unwrap();

    assert_eq!(status, GraphStatus::Skipped);
    let mut storage = local_db.acquire().await.unwrap();
    let updated = storage.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated.status, GraphStatus::Skipped.to_string());
}

#[tokio::test]
#[serial]
async fn refresh_graph_operator_presigned_to_obsoleted_on_prekickoff() {
    let _env_guard = TestEnvGuard::new();
    let (local_db, btc_client, btc_mock, goat_client, _goat_mock, _db_file) = setup_db().await;
    let instance_id = Uuid::new_v4();
    let simplified_graph = build_test_simplified_graph(instance_id);
    store_graph(&local_db, &simplified_graph).await.unwrap();
    let graph_id = simplified_graph.parameters.graph_id;

    let full_graph = bitvm2_lib::types::Bitvm2Graph::from_simplified(&simplified_graph).unwrap();
    let prekickoff_txid = full_graph.cur_prekickoff.tx().compute_txid();

    let tx = Tx {
        txid: prekickoff_txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![Vout {
            scriptpubkey: test_address(env::get_network()).script_pubkey(),
            value: 1000,
        }],
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
    btc_mock.set_tx(prekickoff_txid, tx);

    set_graph_status(&local_db, graph_id, GraphStatus::OperatorPresigned).await;
    let (status, _) = refresh_graph(
        &local_db,
        &btc_client,
        &goat_client,
        instance_id,
        graph_id,
        None,
        Some(GraphStatus::OperatorPresigned),
        None,
    )
    .await
    .unwrap();

    assert_eq!(status, GraphStatus::Obsoleted);
    let mut storage = local_db.acquire().await.unwrap();
    let updated = storage.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated.status, GraphStatus::Obsoleted.to_string());
}

#[tokio::test]
#[serial]
async fn refresh_graph_committee_presigned_to_obsoleted_on_prekickoff() {
    let _env_guard = TestEnvGuard::new();
    let (local_db, btc_client, btc_mock, goat_client, goat_mock, _db_file) = setup_db().await;
    let instance_id = Uuid::new_v4();
    let simplified_graph = build_test_simplified_graph(instance_id);
    store_graph(&local_db, &simplified_graph).await.unwrap();
    let graph_id = simplified_graph.parameters.graph_id;

    let graph_data = GraphData {
        operator_pubkey_prefix: 0,
        operator_pubkey: [0u8; 32],
        pegin_txid: [0u8; 32],
        kickoff_txid: [0u8; 32],
        take1_txid: [0u8; 32],
        take2_txid: [0u8; 32],
        commit_timout_txid: [0u8; 32],
        assert_timeout_txids: vec![],
        nack_txids: vec![],
    };
    goat_mock.set_graph_data(*graph_id.as_bytes(), graph_data);

    let full_graph = bitvm2_lib::types::Bitvm2Graph::from_simplified(&simplified_graph).unwrap();
    let prekickoff_txid = full_graph.cur_prekickoff.tx().compute_txid();
    let tx = Tx {
        txid: prekickoff_txid,
        version: 2,
        locktime: 0,
        vin: vec![],
        vout: vec![Vout {
            scriptpubkey: test_address(env::get_network()).script_pubkey(),
            value: 1000,
        }],
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
    btc_mock.set_tx(prekickoff_txid, tx);

    set_graph_status(&local_db, graph_id, GraphStatus::CommitteePresigned).await;
    let (status, _) = refresh_graph(
        &local_db,
        &btc_client,
        &goat_client,
        instance_id,
        graph_id,
        None,
        Some(GraphStatus::CommitteePresigned),
        None,
    )
    .await
    .unwrap();

    assert_eq!(status, GraphStatus::Obsoleted);
    let mut storage = local_db.acquire().await.unwrap();
    let updated = storage.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated.status, GraphStatus::Obsoleted.to_string());
}

#[tokio::test]
#[serial]
async fn refresh_graph_operator_data_pushed_to_obsoleted_by_status() {
    let _env_guard = TestEnvGuard::new();
    let (local_db, btc_client, _btc_mock, goat_client, goat_mock, _db_file) = setup_db().await;
    let instance_id = Uuid::new_v4();
    let simplified_graph = build_test_simplified_graph(instance_id);
    store_graph(&local_db, &simplified_graph).await.unwrap();
    let graph_id = simplified_graph.parameters.graph_id;

    let pegin_data = PeginData {
        status: PeginStatus::Pending,
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats: 100000,
        txn_fees: [100, 100, 100],
        user_inputs: vec![GoatUtxo { txid: [1u8; 32], vout: 0, amount_sats: 200000 }],
        user_xonly_pubkey: test_xonly_pubkey(),
        user_change_addr: test_address(env::get_network()).to_string(),
        user_refund_addr: test_address(env::get_network()).to_string(),
        pegin_txid: [3u8; 32],
        created_at: 0,
        committee_addresses: vec![],
        committee_pubkeys: vec![],
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

    let withdraw_data = WithdrawData {
        pegin_txid: [0u8; 32],
        operator_address: [0u8; 20],
        status: WithdrawStatus::None,
        instance_id: *instance_id.as_bytes(),
        lock_amount: U256::ZERO,
        btc_block_height_withdraw: U256::ZERO,
    };
    goat_mock.set_withdraw_data(*graph_id.as_bytes(), withdraw_data);

    set_graph_status(&local_db, graph_id, GraphStatus::OperatorDataPushed).await;
    let (status, _) = refresh_graph(
        &local_db,
        &btc_client,
        &goat_client,
        instance_id,
        graph_id,
        None,
        Some(GraphStatus::OperatorDataPushed),
        None,
    )
    .await
    .unwrap();

    assert_eq!(status, GraphStatus::Obsoleted);
    let mut storage = local_db.acquire().await.unwrap();
    let updated = storage.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated.status, GraphStatus::Obsoleted.to_string());
}

#[tokio::test]
#[serial]
async fn refresh_graph_challenge_to_disprove_by_take2_connector_spend() {
    let _env_guard = TestEnvGuard::new();
    let (local_db, btc_client, btc_mock, goat_client, _goat_mock, _db_file) = setup_db().await;
    let instance_id = Uuid::new_v4();
    let simplified_graph = build_test_simplified_graph(instance_id);
    store_graph(&local_db, &simplified_graph).await.unwrap();
    let graph_id = simplified_graph.parameters.graph_id;

    let full_graph = bitvm2_lib::types::Bitvm2Graph::from_simplified(&simplified_graph).unwrap();
    let kickoff_txid = full_graph.kickoff.tx().compute_txid();
    let take2_txid = full_graph.take2.tx().compute_txid();
    let other_txid = BitcoinTxid::from_byte_array([4u8; 32]);

    btc_mock.set_output_status(
        kickoff_txid,
        KICKOFF_TAKE2_VOUT,
        esplora_client::OutputStatus {
            spent: true,
            txid: Some(other_txid),
            vin: Some(0),
            status: Some(TxStatus {
                confirmed: true,
                block_height: Some(200),
                block_hash: None,
                block_time: None,
            }),
        },
    );

    set_graph_status(&local_db, graph_id, GraphStatus::Challenge).await;
    let (status, sub_status) = refresh_graph(
        &local_db,
        &btc_client,
        &goat_client,
        instance_id,
        graph_id,
        None,
        Some(GraphStatus::Challenge),
        None,
    )
    .await
    .unwrap();

    assert_eq!(status, GraphStatus::Disprove);
    assert!(sub_status.is_some());
    let mut storage = local_db.acquire().await.unwrap();
    let updated = storage.find_graph(&graph_id).await.unwrap().unwrap();
    assert_eq!(updated.status, GraphStatus::Disprove.to_string());
    let saved_sub: bitvm2_noded::scheduled_tasks::graph_maintenance_tasks::ChallengeSubStatus =
        serde_json::from_str(&updated.sub_status).unwrap();
    assert!(saved_sub.disprove_type.is_some());
    assert_ne!(take2_txid, other_txid);
}

#[tokio::test]
#[serial]
async fn update_graph_status_committee_presigned_updates_instance() {
    let _env_guard = TestEnvGuard::new();
    let (local_db, _btc_client, _btc_mock, _goat_client, _goat_mock, _db_file) = setup_db().await;
    let instance_id = Uuid::new_v4();
    let graph_id = Uuid::new_v4();

    let instance = Instance {
        instance_id,
        is_bridge_in: true,
        network: env::get_network().to_string(),
        status: InstanceBridgeInStatus::UserInited.to_string(),
        input_utxos: "[]".to_string(),
        fees: UInt64Array3([0, 0, 0]),
        created_at: 0,
        ..Default::default()
    };
    let graph = Graph {
        graph_id,
        instance_id,
        status: GraphStatus::OperatorPresigned.to_string(),
        created_at: 0,
        ..Default::default()
    };

    {
        let mut storage = local_db.acquire().await.unwrap();
        storage.upsert_instance(&instance).await.unwrap();
        storage.upsert_graph(&graph).await.unwrap();
    }

    update_graph_status(&local_db, instance_id, graph_id, GraphStatus::CommitteePresigned, None)
        .await
        .unwrap();

    let mut storage = local_db.acquire().await.unwrap();
    let updated_instance = storage.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(updated_instance.status, InstanceBridgeInStatus::Presigned.to_string());
}
