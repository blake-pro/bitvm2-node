use bitcoin::hashes::Hash;
use bitcoin::{Amount, Network, OutPoint, PublicKey, Txid as BitcoinTxid};
use bitvm2_lib::actors::Actor;
use bitvm2_lib::keys::OperatorMasterKey;
use bitvm2_lib::operator::generate_bitvm_graph;
use bitvm2_lib::types::{
    Bitvm2GraphParameters, Bitvm2InstanceParameters, PrekickoffParameters, SimplifiedBitvm2Graph,
    UserInfo,
};
use bitvm2_noded::action::{ConfirmInstance, GOATMessageContent, PeginRequest};
use bitvm2_noded::env;
use bitvm2_noded::handle::{HandlerContext, dispatch};
use bitvm2_noded::middleware::AllBehaviours;
use bitvm2_noded::middleware::behaviour::AllBehavioursEvent;
use bitvm2_noded::middleware::get_topic_name;
use bitvm2_noded::utils::{read_instance_info_from_goat, store_graph, todo_funcs};
use client::btc_chain::{BTCClient, mock_bitcoin_adaptor::MockBitcoinAdaptor};
use client::goat_chain::{
    GOATClient, PeginData, PeginStatus, Utxo as GoatUtxo, mock_goat_adaptor::MockAdaptor,
};
use client::http_client::async_client::HttpAsyncClient;
use esplora_client::{OutputStatus, Tx, TxStatus, Vout};
use futures::StreamExt;
use goat::connectors::kickoff_connectors::{
    ForceSkipConnector, KickoffConnector, PrekickoffConnector,
};
use goat::contexts::base::generate_n_of_n_public_key;
use goat::disprove_scripts::hash160;
use goat::scripts::p2a_script;
use goat::transactions::base::Input;
use goat::transactions::prekickoff::PrekickoffTransaction;
use libp2p::PeerId;
use libp2p::Swarm;
use libp2p::Transport;
use libp2p::core::transport::dummy::DummyTransport;
use libp2p::gossipsub::{self, MessageId};
use libp2p::identity;
use libp2p::swarm::Config as SwarmConfig;
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux};
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serial_test::serial;
use std::time::Duration;
use store::{
    ByteArray32, Instance, InstanceBridgeInStatus, UInt64Array3, create_local_db, localdb::LocalDB,
};
use tempfile::NamedTempFile;
use tokio::time::Instant;
use uuid::Uuid;
use zkm_sdk::ZKM_CIRCUIT_VERSION;

const PROPTEST_CASES: u32 = 100;

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
            std::env::set_var(env::ENV_BITCOIN_NETWORK, "testnet4");
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

fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: PROPTEST_CASES,
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"),
        )),
        source_file: Some(file!()),
        ..ProptestConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn dispatch_pegin_request_committee_once() {
    let _env_guard = TestEnvGuard::new();
    let instance_id = Uuid::new_v4();
    let input_txid = [1u8; 32];
    let pegin_amount = 100_000u64;
    let input_amount = 200_000u64;
    let (local_db, btc_client, _btc_mock, goat_client, goat_mock, _db_file) =
        setup_pegin_request_fixtures(instance_id, input_txid, input_amount, pegin_amount).await;
    goat_mock.set_committee_member([0u8; 20], true);

    let mut swarm = build_swarm();
    let http_client = HttpAsyncClient::new(None);
    let from_peer_id = PeerId::random();
    let message_id = MessageId::new(b"pegin_committee_once");
    let mut ctx = HandlerContext {
        swarm: &mut swarm,
        local_db: &local_db,
        btc_client: &btc_client,
        goat_client: &goat_client,
        http_client: &http_client,
        actor: Actor::Committee,
        from_peer_id,
        id: message_id,
        is_self_peer: false,
    };
    let content = GOATMessageContent::PeginRequest(PeginRequest {
        instance_id,
        pegin_request_tx_hash: "0xpegin".into(),
        pegin_request_height: 10,
        pegin_timestamp: 123,
    });
    dispatch(&mut ctx, &content).await.unwrap();

    assert_eq!(goat_mock.get_gateway_answer_pegin_request_calls(), 1);
}

fn build_swarm() -> Swarm<AllBehaviours> {
    let identity_key = identity::Keypair::generate_ed25519();
    let peer_id = identity_key.public().to_peer_id();
    let transport = DummyTransport::new().boxed();
    let behaviour = AllBehaviours::new(&identity_key);
    Swarm::new(transport, behaviour, peer_id, SwarmConfig::with_tokio_executor())
}

fn build_network_swarm() -> Swarm<AllBehaviours> {
    let identity_key = identity::Keypair::generate_ed25519();
    libp2p::SwarmBuilder::with_existing_identity(identity_key.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .expect("create tcp transport")
        .with_behaviour(AllBehaviours::new)
        .expect("create behaviour")
        .build()
}

async fn connect_swarms_with_topic(
    swarm_a: &mut Swarm<AllBehaviours>,
    swarm_b: &mut Swarm<AllBehaviours>,
    topic: &gossipsub::IdentTopic,
) {
    swarm_a.behaviour_mut().gossipsub.subscribe(topic).unwrap();
    swarm_b.behaviour_mut().gossipsub.subscribe(topic).unwrap();

    swarm_b.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    let listen_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm_b.select_next_some().await {
            break address;
        }
    };
    swarm_a.dial(listen_addr).unwrap();

    let peer_a = *swarm_a.local_peer_id();
    let peer_b = *swarm_b.local_peer_id();
    let topic_hash = topic.hash();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let a_has_b = swarm_a
            .behaviour()
            .gossipsub
            .all_peers()
            .any(|(peer, topics)| peer == &peer_b && topics.contains(&&topic_hash));
        let b_has_a = swarm_b
            .behaviour()
            .gossipsub
            .all_peers()
            .any(|(peer, topics)| peer == &peer_a && topics.contains(&&topic_hash));
        if a_has_b && b_has_a {
            break;
        }
        if Instant::now() > deadline {
            panic!("timeout waiting for gossipsub subscriptions to propagate");
        }
        tokio::select! {
            _ = swarm_a.select_next_some() => {},
            _ = swarm_b.select_next_some() => {},
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
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

fn test_committee_pubkeys_bytes() -> Vec<Vec<u8>> {
    let pk1 = test_keypair_from_byte(2).public_key();
    let pk2 = test_keypair_from_byte(3).public_key();
    vec![pk1.serialize().to_vec(), pk2.serialize().to_vec()]
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

async fn insert_minimal_instance(local_db: &LocalDB, instance_id: Uuid) {
    let mut storage_processor = local_db.acquire().await.unwrap();
    let current_time = 0;
    let instance = Instance {
        instance_id,
        is_bridge_in: true,
        network: env::get_network().to_string(),
        from_addr: "".to_string(),
        to_addr: "".to_string(),
        amount: 0,
        fees: UInt64Array3([0, 0, 0]),
        input_utxos: "[]".to_string(),
        status: InstanceBridgeInStatus::UserInited.to_string(),
        goat_tx_hash: "".to_string(),
        goat_tx_height: 0,
        user_xonly_pubkey: ByteArray32([0u8; 32]),
        user_change_addr: "".to_string(),
        user_refund_addr: "".to_string(),
        btc_txid: None,
        btc_height: 0,
        pegin_confirm_txid: None,
        pegin_cancel_txid: None,
        committees_answers: Default::default(),
        pegin_data_tx_hash: "".to_string(),
        parameters: None,
        escrow_hash: None,
        bridge_out_lock_time: 0,
        post_pegin_txhash: None,
        bridge_out_amount: "0".to_string(),
        status_updated_at: current_time,
        created_at: current_time,
        updated_at: current_time,
    };
    storage_processor.upsert_instance(&instance).await.unwrap();
}

async fn setup_pegin_request_fixtures(
    instance_id: Uuid,
    input_txid: [u8; 32],
    input_amount: u64,
    pegin_amount_sats: u64,
) -> (LocalDB, BTCClient, MockBitcoinAdaptor, GOATClient, MockAdaptor, NamedTempFile) {
    let db_file = NamedTempFile::new().unwrap();
    let local_db = create_local_db(&format!("sqlite:{}", db_file.path().display())).await;
    let (btc_client, btc_mock) = BTCClient::new_mock_client();
    let (goat_client, goat_mock) = GOATClient::new_mock_client();

    let network = Network::Testnet4;
    let user_change_address = test_address(network);
    let user_refund_address = user_change_address.clone();

    let pegin_data = PeginData {
        status: PeginStatus::Pending,
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats,
        txn_fees: [100, 100, 100],
        user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: input_amount }],
        user_xonly_pubkey: test_xonly_pubkey(),
        user_change_addr: user_change_address.to_string(),
        user_refund_addr: user_refund_address.to_string(),
        pegin_txid: [3u8; 32],
        created_at: 0,
        committee_addresses: vec![],
        committee_pubkeys: vec![],
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);
    goat_mock.reset_gateway_answer_pegin_request_calls();

    let btc_txid = BitcoinTxid::from_byte_array(input_txid);
    btc_mock.set_output_status(
        btc_txid,
        0,
        OutputStatus { spent: false, txid: None, vin: None, status: None },
    );
    btc_mock.set_tx(
        btc_txid,
        Tx {
            txid: btc_txid,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![Vout {
                scriptpubkey: user_change_address.script_pubkey(),
                value: input_amount,
            }],
            status: TxStatus {
                confirmed: true,
                block_height: Some(1),
                block_hash: None,
                block_time: None,
            },
            fee: 100,
            size: 100,
            weight: 400,
        },
    );

    (local_db, btc_client, btc_mock, goat_client, goat_mock, db_file)
}

async fn setup_confirm_instance_fixtures(
    instance_id: Uuid,
    input_txid: [u8; 32],
    input_amount: u64,
    pegin_amount_sats: u64,
) -> (
    LocalDB,
    BTCClient,
    MockBitcoinAdaptor,
    GOATClient,
    MockAdaptor,
    NamedTempFile,
    Bitvm2InstanceParameters,
) {
    let db_file = NamedTempFile::new().unwrap();
    let local_db = create_local_db(&format!("sqlite:{}", db_file.path().display())).await;
    let (btc_client, btc_mock) = BTCClient::new_mock_client();
    let (goat_client, goat_mock) = GOATClient::new_mock_client();

    insert_minimal_instance(&local_db, instance_id).await;

    let network = Network::Testnet4;
    let user_change_address = test_address(network);
    let user_refund_address = user_change_address.clone();
    let committee_pubkeys = test_committee_pubkeys_bytes();
    goat_mock.set_committee_pubkeys(committee_pubkeys.clone());

    let pegin_data = PeginData {
        status: PeginStatus::Pending,
        instance_id: *instance_id.as_bytes(),
        depositor_address: [0u8; 20],
        pegin_amount_sats,
        txn_fees: [100, 100, 100],
        user_inputs: vec![GoatUtxo { txid: input_txid, vout: 0, amount_sats: input_amount }],
        user_xonly_pubkey: test_xonly_pubkey(),
        user_change_addr: user_change_address.to_string(),
        user_refund_addr: user_refund_address.to_string(),
        pegin_txid: [3u8; 32],
        created_at: 0,
        committee_addresses: vec![],
        committee_pubkeys,
    };
    goat_mock.set_pegin_data(*instance_id.as_bytes(), pegin_data);

    let instance_params = read_instance_info_from_goat(&goat_client, instance_id).await.unwrap();
    let pegin_deposit_txid = instance_params.build_pegin_tx().unwrap().0.tx().compute_txid();
    btc_mock.set_tx(
        pegin_deposit_txid,
        Tx {
            txid: pegin_deposit_txid,
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![Vout {
                scriptpubkey: user_change_address.script_pubkey(),
                value: input_amount,
            }],
            status: TxStatus {
                confirmed: true,
                block_height: Some(1),
                block_hash: None,
                block_time: None,
            },
            fee: 100,
            size: 100,
            weight: 400,
        },
    );

    (local_db, btc_client, btc_mock, goat_client, goat_mock, db_file, instance_params)
}

#[test]
#[serial]
fn prop_dispatch_pegin_request_committee_calls_gateway_answer() {
    let _env_guard = TestEnvGuard::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let strategy = (
        any::<[u8; 16]>(),
        any::<[u8; 32]>(),
        1u64..200_000u64,
        1i64..10_000i64,
        1i64..1_000_000i64,
    );
    let mut runner = TestRunner::new(proptest_config());
    runner
        .run(&strategy, |(instance_bytes, input_txid, pegin_amount, height, timestamp)| {
            let instance_id = Uuid::from_bytes(instance_bytes);
            let input_amount = pegin_amount.saturating_add(1000);
            let pegin_hash = format!("0x{}", hex::encode(input_txid));
            rt.block_on(async {
                let (local_db, btc_client, _btc_mock, goat_client, goat_mock, _db_file) =
                    setup_pegin_request_fixtures(
                        instance_id,
                        input_txid,
                        input_amount,
                        pegin_amount,
                    )
                    .await;
                goat_mock.set_committee_member([0u8; 20], true);
                let mut swarm = build_swarm();
                let http_client = HttpAsyncClient::new(None);
                let from_peer_id = PeerId::random();
                let message_id = MessageId::new(b"pegin_committee");
                let mut ctx = HandlerContext {
                    swarm: &mut swarm,
                    local_db: &local_db,
                    btc_client: &btc_client,
                    goat_client: &goat_client,
                    http_client: &http_client,
                    actor: Actor::Committee,
                    from_peer_id,
                    id: message_id,
                    is_self_peer: false,
                };
                let content = GOATMessageContent::PeginRequest(PeginRequest {
                    instance_id,
                    pegin_request_tx_hash: pegin_hash,
                    pegin_request_height: height,
                    pegin_timestamp: timestamp,
                });
                prop_assert!(dispatch(&mut ctx, &content).await.is_ok());
                prop_assert_eq!(goat_mock.get_gateway_answer_pegin_request_calls(), 1);

                let mut storage_processor = local_db.acquire().await.unwrap();
                let instance = storage_processor.find_instance(&instance_id).await.unwrap();
                prop_assert!(instance.is_some());
                prop_assert_eq!(
                    instance.unwrap().status,
                    InstanceBridgeInStatus::UserInited.to_string()
                );

                Ok(())
            })
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_dispatch_pegin_request_non_committee_no_gateway_answer() {
    let _env_guard = TestEnvGuard::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let strategy = (
        any::<[u8; 16]>(),
        any::<[u8; 32]>(),
        1u64..200_000u64,
        1i64..10_000i64,
        1i64..1_000_000i64,
    );
    let mut runner = TestRunner::new(proptest_config());
    runner
        .run(&strategy, |(instance_bytes, input_txid, pegin_amount, height, timestamp)| {
            let instance_id = Uuid::from_bytes(instance_bytes);
            let input_amount = pegin_amount.saturating_add(1000);
            let pegin_hash = format!("0x{}", hex::encode(input_txid));
            rt.block_on(async {
                let (local_db, btc_client, _btc_mock, goat_client, goat_mock, _db_file) =
                    setup_pegin_request_fixtures(
                        instance_id,
                        input_txid,
                        input_amount,
                        pegin_amount,
                    )
                    .await;
                let mut swarm = build_swarm();
                let http_client = HttpAsyncClient::new(None);
                let from_peer_id = PeerId::random();
                let message_id = MessageId::new(b"pegin_non_committee");
                let mut ctx = HandlerContext {
                    swarm: &mut swarm,
                    local_db: &local_db,
                    btc_client: &btc_client,
                    goat_client: &goat_client,
                    http_client: &http_client,
                    actor: Actor::Operator,
                    from_peer_id,
                    id: message_id,
                    is_self_peer: false,
                };
                let content = GOATMessageContent::PeginRequest(PeginRequest {
                    instance_id,
                    pegin_request_tx_hash: pegin_hash,
                    pegin_request_height: height,
                    pegin_timestamp: timestamp,
                });
                prop_assert!(dispatch(&mut ctx, &content).await.is_ok());
                prop_assert_eq!(goat_mock.get_gateway_answer_pegin_request_calls(), 0);

                let mut storage_processor = local_db.acquire().await.unwrap();
                let instance = storage_processor.find_instance(&instance_id).await.unwrap();
                prop_assert!(instance.is_some());
                prop_assert_eq!(
                    instance.unwrap().status,
                    InstanceBridgeInStatus::UserInited.to_string()
                );

                Ok(())
            })
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_dispatch_confirm_instance_operator_sends_create_graph() {
    let _env_guard = TestEnvGuard::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let strategy = any::<[u8; 16]>();
    let mut runner = TestRunner::new(proptest_config());
    runner
        .run(&strategy, |instance_bytes| {
            let instance_id = Uuid::from_bytes(instance_bytes);
            rt.block_on(async {
                let db_file = NamedTempFile::new().unwrap();
                let local_db =
                    create_local_db(&format!("sqlite:{}", db_file.path().display())).await;
                let (btc_client, _btc_mock) = BTCClient::new_mock_client();
                let (goat_client, _goat_mock) = GOATClient::new_mock_client();
                let mut swarm = build_network_swarm();
                let mut receiver_swarm = build_network_swarm();
                let topic = gossipsub::IdentTopic::new(get_topic_name(&Actor::All.to_string()));
                connect_swarms_with_topic(&mut swarm, &mut receiver_swarm, &topic).await;
                let http_client = HttpAsyncClient::new(None);
                let from_peer_id = *receiver_swarm.local_peer_id();
                let message_id = MessageId::new(b"confirm_instance_operator");

                let simplified_graph = build_test_simplified_graph(instance_id);
                store_graph(&local_db, &simplified_graph).await.unwrap();

                let mut ctx = HandlerContext {
                    swarm: &mut swarm,
                    local_db: &local_db,
                    btc_client: &btc_client,
                    goat_client: &goat_client,
                    http_client: &http_client,
                    actor: Actor::Operator,
                    from_peer_id,
                    id: message_id,
                    is_self_peer: false,
                };
                let content = GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id });
                let dispatch_result = dispatch(&mut ctx, &content).await;
                prop_assert!(
                    dispatch_result.is_ok(),
                    "dispatch failed: {:#}",
                    dispatch_result.unwrap_err()
                );

                let mut received = false;
                let deadline = Instant::now() + Duration::from_secs(5);
                while !received && Instant::now() < deadline {
                    tokio::select! {
                        event = swarm.select_next_some() => {
                            let _ = event;
                        }
                        event = receiver_swarm.select_next_some() => {
                            if let SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(
                                gossipsub::Event::Message { .. }
                            )) = event {
                                received = true;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                    }
                }
                prop_assert!(received, "did not receive gossipsub message");

                Ok(())
            })
        })
        .unwrap();
}

#[test]
#[serial]
fn prop_dispatch_confirm_instance_non_operator_stores_parameters() {
    let _env_guard = TestEnvGuard::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let strategy = (any::<[u8; 16]>(), any::<[u8; 32]>(), 1u64..200_000u64);
    let mut runner = TestRunner::new(proptest_config());
    runner
        .run(&strategy, |(instance_bytes, input_txid, pegin_amount)| {
            let instance_id = Uuid::from_bytes(instance_bytes);
            let input_amount = pegin_amount.saturating_add(1000);
            rt.block_on(async {
                let (local_db, btc_client, _btc_mock, goat_client, _goat_mock, _db_file, _) =
                    setup_confirm_instance_fixtures(
                        instance_id,
                        input_txid,
                        input_amount,
                        pegin_amount,
                    )
                    .await;
                let mut swarm = build_swarm();
                let http_client = HttpAsyncClient::new(None);
                let from_peer_id = PeerId::random();
                let message_id = MessageId::new(b"confirm_instance_default");
                let mut ctx = HandlerContext {
                    swarm: &mut swarm,
                    local_db: &local_db,
                    btc_client: &btc_client,
                    goat_client: &goat_client,
                    http_client: &http_client,
                    actor: Actor::Committee,
                    from_peer_id,
                    id: message_id,
                    is_self_peer: false,
                };
                let content = GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id });
                prop_assert!(dispatch(&mut ctx, &content).await.is_ok());

                let mut storage_processor = local_db.acquire().await.unwrap();
                let instance = storage_processor.find_instance(&instance_id).await.unwrap();
                prop_assert!(instance.is_some());
                prop_assert!(instance.unwrap().parameters.is_some());

                Ok(())
            })
        })
        .unwrap();
}
