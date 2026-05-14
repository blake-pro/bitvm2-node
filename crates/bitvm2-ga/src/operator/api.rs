use crate::keys::hkdf_derive_bytes;
use crate::types::{
    Bitvm2Graph, Bitvm2GraphParameters, Groth16Proof, GuestInputs,
    OperatorGuestAssertWotsPublicKeys, OperatorWotsPublicKeys, OperatorWotsSecretKeys,
    OperatorWotsSignatures, PublicInputs, VerifyingKey, WrapperChallengeGuestValues,
};
use anyhow::{Result, bail};
use bitcoin::{Address, Amount, Network, PublicKey, ScriptBuf, Transaction, TxIn};
use bitcoin::{OutPoint, Witness, XOnlyPublicKey, key::Keypair};
use bitvm::chunk::api::{
    NUM_HASH, NUM_PUBS, NUM_U256, PublicKeys as Groth16WotsPublicKeys,
    api_generate_full_tapscripts, api_generate_partial_script, generate_assertions,
};
use bitvm::signatures::{HASH_LEN, WinternitzSecret, Wots, Wots16, Wots32};
use bitvm::treepp::*;
use goat::connectors::assert_connectors::{AssertCommitConnector, chunk_assert_commit};
use goat::connectors::base::TaprootConnector;
use goat::connectors::connector_0::Connector0;
use goat::connectors::connector_a::ConnectorA;
use goat::connectors::connector_b::ConnectorB;
use goat::connectors::connector_c::ConnectorC;
use goat::connectors::connector_d::ConnectorD;
use goat::connectors::connector_e::ConnectorE;
use goat::connectors::connector_f::ConnectorF;
use goat::connectors::connector_g::ConnectorG;
use goat::connectors::kickoff_connectors::{
    ForceSkipConnector, GuardianConnector, KickoffConnector, PrekickoffConnector,
};
use goat::connectors::watchtower_connectors::{
    AckConnector, WatchctowerConnectors, WatchtowerChallengeConnector,
};
use goat::constants::{
    CONNECTOR_A_TIMELOCK, CONNECTOR_D_TIMELOCK, CONNECTOR_F_TIMELOCK, WATCHTOWER_CHALLENGE_TIMELOCK,
};
use goat::disprove_scripts::{
    GUEST_PUBIN_COMMITMENT_INDEX, GUEST_VALIDATION_TAPS, NUM_GUEST, NUM_GUEST_PUBS_EXTRA, hash160,
    verify_constant_pubin_script,
};
use goat::transactions::assert::{AssertCommitTimeoutTransaction, AssertInitTransaction};
use goat::transactions::base::{DUST_AMOUNT, Input};
use goat::transactions::challenge::ChallengeTransaction;
use goat::transactions::kickoff::KickoffTransaction;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::prekickoff::{
    ChallengeIncompleteKickoffTransaction, ForceSkipKickoffTransaction, PrekickoffTransaction,
    QuickChallengeTransaction, operator_skip_kickoff,
};
use goat::transactions::signing::populate_taproot_txin_witness;
use goat::transactions::take1::Take1Transaction;
use goat::transactions::take2::Take2Transaction;
use goat::transactions::watchtower_challenge::{
    BlockhashCommitTimeoutTransaction, NackTransaction, WatchtowerChallengeInitTransaction,
    WatchtowerChallengeTimeoutTransaction, operator_ack, operator_commit_blockhash,
};
use goat::utils::num_blocks_per_network;
use hex::encode as hex_encode;
use uuid::Uuid;

const OPERATOR_WOTS_HKDF_SALT: &[u8] = b"bitvm2/operator-wots/v1";

pub fn generate_wots_keys(seed: &str) -> (OperatorWotsSecretKeys, OperatorWotsPublicKeys) {
    let secrets = wots_seed_to_secrets(seed);
    let pubkeys = wots_secrets_to_pubkeys(&secrets);
    (secrets, pubkeys)
}

pub fn operator_presig_num() -> usize {
    6
}

#[allow(deprecated)]
pub fn wots_secrets_to_pubkeys(secrets: &OperatorWotsSecretKeys) -> OperatorWotsPublicKeys {
    let mut index = 0;

    let mut guest_extra = vec![];
    for _ in 0..NUM_GUEST_PUBS_EXTRA {
        guest_extra.push(Wots32::generate_public_key(&secrets[index]));
        index += 1;
    }

    let guest_graph_id = [Wots16::generate_public_key(&secrets[index])];
    index += 1;
    let guest_genesis = [Wots32::generate_public_key(&secrets[index])];
    index += 1;

    let mut pubins = vec![];
    for _ in 0..NUM_PUBS {
        pubins.push(Wots32::generate_public_key(&secrets[index]));
        index += 1;
    }
    let mut fq_arr = vec![];
    for _ in 0..NUM_U256 {
        fq_arr.push(Wots32::generate_public_key(&secrets[index]));
        index += 1;
    }
    let mut h_arr = vec![];
    for _ in 0..NUM_HASH {
        h_arr.push(Wots16::generate_public_key(&secrets[index]));
        index += 1;
    }

    let g16_wotspubkey: Groth16WotsPublicKeys =
        (pubins.try_into().unwrap(), fq_arr.try_into().unwrap(), h_arr.try_into().unwrap());
    (
        guest_extra.try_into().unwrap(),
        OperatorGuestAssertWotsPublicKeys {
            graph_id: guest_graph_id,
            genesis_sequencer_commit_txid: guest_genesis,
        },
        Box::new(g16_wotspubkey),
    )
}

#[allow(deprecated)]
pub fn wots_seed_to_secrets(seed: &str) -> OperatorWotsSecretKeys {
    let seed_bytes = seed.as_bytes();
    fn derive_secret<W: Wots>(
        seed_bytes: &[u8],
        label: &str,
        type_flag: u16,
        index: usize,
    ) -> WinternitzSecret {
        let sec_i = hex_encode(hkdf_derive_bytes(
            seed_bytes,
            OPERATOR_WOTS_HKDF_SALT,
            label.as_bytes(),
            32,
        ));
        let sec_str = format!("{sec_i}{type_flag:04x}{index:04x}");
        W::secret_from_str(&sec_str)
    }

    let mut secrets = Vec::with_capacity(NUM_GUEST + NUM_PUBS + NUM_U256 + NUM_HASH);
    let mut index = 0;
    secrets.push(derive_secret::<Wots32>(seed_bytes, "guest-extra/operator-vk", 1, index));
    index += 1;
    secrets.push(derive_secret::<Wots16>(seed_bytes, "guest-assert/graph-id", 0, index));
    index += 1;
    secrets.push(derive_secret::<Wots32>(seed_bytes, "guest-assert/genesis-txid", 1, index));
    index += 1;
    for i in 0..NUM_PUBS {
        secrets.push(derive_secret::<Wots32>(seed_bytes, &format!("groth16/pubin/{i}"), 1, index));
        index += 1;
    }
    for i in 0..NUM_U256 {
        secrets.push(derive_secret::<Wots32>(seed_bytes, &format!("groth16/u256/{i}"), 1, index));
        index += 1;
    }
    for i in 0..NUM_HASH {
        secrets.push(derive_secret::<Wots16>(seed_bytes, &format!("groth16/hash/{i}"), 0, index));
        index += 1;
    }

    Box::new(secrets.try_into().unwrap())
}

pub fn generate_partial_scripts(ark_vkey: &VerifyingKey) -> Vec<ScriptBuf> {
    api_generate_partial_script(ark_vkey)
}

pub fn wrapper_challenge_guest_values(
    operator_vk_hash: [u8; 32],
    graph_id: Uuid,
    genesis_sequencer_commit_txid: [u8; 32],
) -> WrapperChallengeGuestValues {
    WrapperChallengeGuestValues {
        operator_vk_hash,
        graph_id: *graph_id.as_bytes(),
        genesis_sequencer_commit_txid,
    }
}

fn discard_witness_preimages(preimage_count: usize) -> Script {
    script! {
        for _ in 0..preimage_count {
            OP_DROP
        }
    }
}

fn verify_constant_inner(constant_value: &[u8]) -> Script {
    script! {
        { 1 }
        for byte in constant_value.to_vec() {
            OP_SWAP
            { byte & 0x0F }
            OP_NUMEQUAL
            OP_BOOLAND

            OP_SWAP
            { byte >> 4 }
            OP_NUMEQUAL
            OP_BOOLAND
        }
    }
}

fn verify_constant_wots16_script(
    wots_pk: &<Wots16 as Wots>::PublicKey,
    constant_value: &[u8; 16],
) -> Script {
    script! {
        { Wots16::checksig_verify(wots_pk) }
        { verify_constant_inner(constant_value) }
    }
}

fn flag_and() -> Script {
    script! {
        OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK
    }
}

pub fn verify_wrapper_guest_pubin(
    operator_vk_wots_pubkey: &<Wots32 as Wots>::PublicKey,
    graph_id_wots_pubkey: &<Wots16 as Wots>::PublicKey,
    genesis_wots_pubkey: &<Wots32 as Wots>::PublicKey,
    groth16_pubin_wots_pubkeys: &[<Wots32 as Wots>::PublicKey; NUM_PUBS],
    wrapper_values: &WrapperChallengeGuestValues,
    watchtower_preimage_count: usize,
) -> [Script; GUEST_VALIDATION_TAPS] {
    let public_values_commitment = wrapper_values.public_values_commitment();
    let scr = script! {
        { 1 } OP_TOALTSTACK

        { verify_constant_pubin_script(genesis_wots_pubkey, &wrapper_values.genesis_sequencer_commit_txid) }
        { flag_and() }

        { discard_witness_preimages(watchtower_preimage_count) }

        { verify_constant_wots16_script(graph_id_wots_pubkey, &wrapper_values.graph_id) }
        { flag_and() }

        { verify_constant_pubin_script(operator_vk_wots_pubkey, &wrapper_values.operator_vk_hash) }
        { flag_and() }

        { verify_constant_pubin_script(&groth16_pubin_wots_pubkeys[GUEST_PUBIN_COMMITMENT_INDEX], &public_values_commitment) }
        { flag_and() }

        OP_FROMALTSTACK
        OP_NOT
    };
    [scr]
}

pub fn generate_disprove_scripts(
    partial_scripts: &[ScriptBuf],
    wots_pubkeys: OperatorWotsPublicKeys,
    wrapper_values: &WrapperChallengeGuestValues,
    watchtower_preimage_count: usize,
) -> (Vec<ScriptBuf>, Vec<ScriptBuf>) {
    let (guest_pubkeys_0, guest_pubkeys_1, proof_pubkeys) = wots_pubkeys;
    let guest_pubin_scripts = verify_wrapper_guest_pubin(
        &guest_pubkeys_0[0],
        &guest_pubkeys_1.graph_id[0],
        &guest_pubkeys_1.genesis_sequencer_commit_txid[0],
        &proof_pubkeys.0,
        wrapper_values,
        watchtower_preimage_count,
    );
    let guest_pubin_scripts = guest_pubin_scripts.into_iter().map(|s| s.compile()).collect();
    let proof_scripts = api_generate_full_tapscripts(*proof_pubkeys, partial_scripts);
    (guest_pubin_scripts, proof_scripts)
}

fn mixed_assert_wots_pubkeys(
    wots_pubkeys: &OperatorWotsPublicKeys,
) -> (Vec<<Wots32 as Wots>::PublicKey>, Vec<<Wots16 as Wots>::PublicKey>) {
    let mut wots32_pubkeys = wots_pubkeys.1.genesis_sequencer_commit_txid.to_vec();
    wots32_pubkeys.extend(wots_pubkeys.2.0.to_vec());
    wots32_pubkeys.extend(wots_pubkeys.2.1.to_vec());

    let mut wots16_pubkeys = wots_pubkeys.1.graph_id.to_vec();
    wots16_pubkeys.extend(wots_pubkeys.2.2.to_vec());

    (wots32_pubkeys, wots16_pubkeys)
}

pub fn generate_mixed_chunked_assert_commit_connectors(
    network: Network,
    n_of_n_taproot_public_key: &XOnlyPublicKey,
    wots_pubkeys: &OperatorWotsPublicKeys,
) -> Vec<AssertCommitConnector> {
    let (wots32_pubkeys, wots16_pubkeys) = mixed_assert_wots_pubkeys(wots_pubkeys);
    let use_compact_wots = false;
    let chunks = chunk_assert_commit(wots32_pubkeys.len(), wots16_pubkeys.len(), use_compact_wots);
    let n32 = wots32_pubkeys.len();

    chunks
        .into_iter()
        .map(|(start_index, wots_num)| {
            let end_index = start_index + wots_num;
            let start32 = start_index.min(n32);
            let end32 = end_index.min(n32);
            let start16 = start_index.saturating_sub(n32);
            let end16 = end_index.saturating_sub(n32);

            AssertCommitConnector::new(
                network,
                n_of_n_taproot_public_key,
                &wots32_pubkeys[start32..end32].to_vec(),
                &wots16_pubkeys[start16..end16].to_vec(),
            )
        })
        .collect()
}

fn mixed_assert_wots_secrets(
    wots_secret_keys: &OperatorWotsSecretKeys,
) -> (Vec<WinternitzSecret>, Vec<WinternitzSecret>) {
    let mut wots32_secret_keys = Vec::with_capacity(1 + NUM_PUBS + NUM_U256);
    wots32_secret_keys.push(wots_secret_keys[2].clone());
    wots32_secret_keys.extend(wots_secret_keys[3..3 + NUM_PUBS + NUM_U256].iter().cloned());

    let mut wots16_secret_keys = Vec::with_capacity(1 + NUM_HASH);
    wots16_secret_keys.push(wots_secret_keys[1].clone());
    wots16_secret_keys.extend(
        wots_secret_keys[3 + NUM_PUBS + NUM_U256..3 + NUM_PUBS + NUM_U256 + NUM_HASH]
            .iter()
            .cloned(),
    );

    (wots32_secret_keys, wots16_secret_keys)
}

#[allow(deprecated)]
pub fn corrupt_proof(
    sigs: &mut OperatorWotsSignatures,
    wots_sec: &OperatorWotsSecretKeys,
    index: usize,
) {
    let mut scramble: [u8; 32] = [1u8; 32];
    scramble[16] = 37;
    let mut scramble2: [u8; HASH_LEN] = [1u8; HASH_LEN];
    scramble2[HASH_LEN / 2] = 37;
    println!("corrupted assertion at index {index}");
    let sec_index = index + NUM_GUEST;
    if index < NUM_PUBS {
        let i = index;
        let assn = scramble;
        let sig = Wots32::sign(&wots_sec[sec_index], &assn);
        sigs.1.0[i] = sig;
    } else if index < NUM_PUBS + NUM_U256 {
        let i = index - NUM_PUBS;
        let assn = scramble;
        let sig = Wots32::sign(&wots_sec[sec_index], &assn);
        sigs.1.1[i] = sig;
    } else if index < NUM_PUBS + NUM_U256 + NUM_HASH {
        let i = index - NUM_PUBS - NUM_U256;
        let assn = scramble2;
        let sig = Wots16::sign(&wots_sec[sec_index], &assn);
        sigs.1.2[i] = sig;
    }
}

pub fn generate_bitvm_graph(
    params: Bitvm2GraphParameters,
    disprove_scripts: Vec<ScriptBuf>,
) -> Result<Bitvm2Graph> {
    let network = params.instance_parameters.network;
    let operator_pubkey = params.operator_pubkey;
    let operator_taproot_public_key = XOnlyPublicKey::from(operator_pubkey);
    let (connector_e, _) =
        ConnectorE::new_with_scripts(network, &operator_taproot_public_key, disprove_scripts);
    generate_bitvm_graph_inner(params, connector_e)
}

pub(crate) fn generate_bitvm_graph_inner(
    params: Bitvm2GraphParameters,
    connector_e: ConnectorE,
) -> Result<Bitvm2Graph> {
    // TODO: check parameters?
    let network = params.instance_parameters.network;
    let operator_pubkey = params.operator_pubkey;
    let operator_taproot_public_key = XOnlyPublicKey::from(operator_pubkey);
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(params.instance_parameters.committee_agg_pubkey);
    let watchtower_num = params.watchtower_pubkeys.len();
    let assert_commit_connectors = generate_mixed_chunked_assert_commit_connectors(
        network,
        &n_of_n_taproot_public_key,
        &params.operator_wots_pubkeys,
    );
    let assert_commit_num = assert_commit_connectors.len();

    // pegin
    let (_, pegin, _) = params.instance_parameters.build_pegin_tx()?;
    let pegin_txid = pegin.tx().compute_txid();
    let connector_0_input = Input {
        outpoint: OutPoint { txid: pegin_txid, vout: 0 },
        amount: pegin.tx().output[0].value,
    };

    // prekickoff
    let cur_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let next_force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    let next_kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let next_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let cur_prekickoff = params.prekickoff_parameters.cur_prekickoff_txn.clone();
    let cur_prekickoff_txid = cur_prekickoff.tx().compute_txid();
    let cur_prekickoff_connector_input = Input {
        outpoint: OutPoint { txid: cur_prekickoff_txid, vout: 2 },
        amount: cur_prekickoff.tx().output[2].value,
    };
    let next_prekickoff = PrekickoffTransaction::new_for_validation(
        &cur_prekickoff_connector,
        &next_force_skip_connector,
        &next_kickoff_connector,
        &next_prekickoff_connector,
        cur_prekickoff_connector_input,
        params.prekickoff_parameters.replenish_fee_inputs.clone(),
        params.prekickoff_parameters.replenish_fee_prev_outs.clone(),
        params.prekickoff_parameters.fee_amount,
        watchtower_num,
        assert_commit_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create pre-kickoff txn: {e}"))?;
    let next_prekickoff_txid = next_prekickoff.tx().compute_txid();
    let next_force_skip_connector_input = Input {
        outpoint: OutPoint { txid: next_prekickoff_txid, vout: 0 },
        amount: cur_prekickoff.tx().output[0].value,
    };
    let next_prekickoff_connector_input = Input {
        outpoint: OutPoint { txid: next_prekickoff_txid, vout: 2 },
        amount: cur_prekickoff.tx().output[2].value,
    };

    // kickoff
    let kickoff_connector_input = Input {
        outpoint: OutPoint { txid: cur_prekickoff_txid, vout: 1 },
        amount: cur_prekickoff.tx().output[1].value,
    };
    let kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let connector_a =
        ConnectorA::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let connector_b = ConnectorB::new(network, &operator_taproot_public_key);
    let connector_c = ConnectorC::new(network, &operator_taproot_public_key);
    let guardian_connector = GuardianConnector::new(network, &operator_taproot_public_key);
    let kickoff = KickoffTransaction::new_for_validation(
        &kickoff_connector,
        &connector_a,
        &connector_b,
        &connector_c,
        &connector_e,
        &guardian_connector,
        &kickoff_connector_input,
        watchtower_num,
        assert_commit_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create kickoff txn: {e}"))?;
    let kickoff_txid = kickoff.tx().compute_txid();
    let connector_a_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 0 },
        amount: kickoff.tx().output[0].value,
    };
    let connector_b_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 1 },
        amount: kickoff.tx().output[1].value,
    };
    let connector_c_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 2 },
        amount: kickoff.tx().output[2].value,
    };
    let connector_e_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 3 },
        amount: kickoff.tx().output[3].value,
    };
    let guardian_connector_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 4 },
        amount: kickoff.tx().output[4].value,
    };

    // prekickoff challenge
    let force_skip_kickoff = ForceSkipKickoffTransaction::new_for_validation(
        &kickoff_connector,
        &next_force_skip_connector,
        kickoff_connector_input,
        next_force_skip_connector_input.clone(),
    );
    let quick_challenge = QuickChallengeTransaction::new_for_validation(
        &guardian_connector,
        &next_force_skip_connector,
        guardian_connector_input.clone(),
        next_force_skip_connector_input,
    );
    let challenge_incomplete_kickoff = ChallengeIncompleteKickoffTransaction::new_for_validation(
        &guardian_connector,
        &next_prekickoff_connector,
        guardian_connector_input.clone(),
        next_prekickoff_connector_input,
    );

    // take-1
    let connector_0 = Connector0::new(network, &n_of_n_taproot_public_key);
    let take1 = Take1Transaction::new_for_validation(
        &connector_0,
        &connector_a,
        &connector_b,
        &connector_c,
        &guardian_connector,
        connector_0_input.clone(),
        connector_a_input.clone(),
        connector_b_input.clone(),
        connector_c_input.clone(),
        guardian_connector_input.clone(),
        &params.operator_receive_address,
    )
    .map_err(|e| anyhow::anyhow!("failed to create take-1 txn: {e}"))?;

    // challenge
    let challenge = ChallengeTransaction::new_for_validation(
        &connector_a,
        connector_a_input,
        params.challenge_amount,
        &params.operator_receive_address,
    );

    // watchtower-challenge-init
    let connector_g = ConnectorG::new(
        network,
        &n_of_n_taproot_public_key,
        &operator_taproot_public_key,
        &params.operator_wots_pubkeys.0[0],
    );
    let connector_f =
        ConnectorF::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let watchtower_connectors_array = (0..watchtower_num)
        .map(|i| {
            (
                WatchtowerChallengeConnector::new(
                    network,
                    &operator_taproot_public_key,
                    &params.watchtower_pubkeys[i],
                ),
                AckConnector::new(network, &n_of_n_taproot_public_key, &params.hashlocks[i]),
            )
        })
        .collect::<Vec<WatchctowerConnectors>>();
    let watchtower_challenge_init = WatchtowerChallengeInitTransaction::new_for_validation(
        &connector_b,
        &connector_g,
        &connector_f,
        &watchtower_connectors_array,
        connector_b_input,
    )
    .map_err(|e| anyhow::anyhow!("failed to create watchtower-challenge-init txn: {e}"))?;
    let watchtower_challenge_init_txid = watchtower_challenge_init.tx().compute_txid();
    let connector_g_vout = watchtower_num * 2;
    let connector_g_input = Input {
        outpoint: OutPoint { txid: watchtower_challenge_init_txid, vout: connector_g_vout as u32 },
        amount: watchtower_challenge_init.tx().output[connector_g_vout].value,
    };
    let connector_f_vout = connector_g_vout + 1;
    let connector_f_input = Input {
        outpoint: OutPoint { txid: watchtower_challenge_init_txid, vout: connector_f_vout as u32 },
        amount: watchtower_challenge_init.tx().output[connector_f_vout].value,
    };

    // watchtower-challenge-timeout & nack
    let mut watchtower_challenge_timeout_txns = vec![];
    let mut nack_txns = vec![];
    for (i, watchtower_connectors) in watchtower_connectors_array.iter().enumerate() {
        let watchtower_challenge_connector_input_vout: usize = i * 2;
        let watchtower_challenge_connector_input = Input {
            outpoint: OutPoint {
                txid: watchtower_challenge_init_txid,
                vout: watchtower_challenge_connector_input_vout as u32,
            },
            amount: watchtower_challenge_init.tx().output
                [watchtower_challenge_connector_input_vout]
                .value,
        };
        let ack_connector_input_vout: usize = i * 2 + 1;
        let ack_connector_input = Input {
            outpoint: OutPoint {
                txid: watchtower_challenge_init_txid,
                vout: ack_connector_input_vout as u32,
            },
            amount: watchtower_challenge_init.tx().output[ack_connector_input_vout].value,
        };
        let watchtower_challenge_timeout_tx =
            WatchtowerChallengeTimeoutTransaction::new_for_validation(
                watchtower_connectors,
                watchtower_challenge_connector_input,
                ack_connector_input.clone(),
            );
        let nack_tx = NackTransaction::new_for_validation(
            watchtower_connectors,
            &connector_f,
            ack_connector_input,
            connector_f_input.clone(),
        );
        watchtower_challenge_timeout_txns.push(watchtower_challenge_timeout_tx);
        nack_txns.push(nack_tx);
    }

    // operator-commit-blockhash-timeout
    let blockhash_commit_timeout = BlockhashCommitTimeoutTransaction::new_for_validation(
        &connector_g,
        &connector_f,
        connector_g_input.clone(),
        connector_f_input.clone(),
    );

    // assert-init
    let connector_d =
        ConnectorD::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let assert_init = AssertInitTransaction::new_for_validation(
        &connector_c,
        &connector_d,
        &assert_commit_connectors,
        &connector_c_input,
    )
    .map_err(|e| anyhow::anyhow!("failed to create assert-init txn: {e}"))?;
    let assert_init_txid = assert_init.tx().compute_txid();
    let connector_d_vout: usize = assert_commit_connectors.len();
    let connector_d_input = Input {
        outpoint: OutPoint { txid: assert_init_txid, vout: connector_d_vout as u32 },
        amount: assert_init.tx().output[connector_d_vout].value,
    };

    // assert-commit-timeout
    let mut assert_commit_timeout_txns = vec![];
    for (i, assert_commit_connector) in assert_commit_connectors.iter().enumerate() {
        let assert_commit_timeout_input_0_vout: usize = i;
        let assert_commit_timeout_input_0 = Input {
            outpoint: OutPoint {
                txid: assert_init_txid,
                vout: assert_commit_timeout_input_0_vout as u32,
            },
            amount: assert_init.tx().output[assert_commit_timeout_input_0_vout].value,
        };
        let assert_commit_timeout_tx = AssertCommitTimeoutTransaction::new_for_validation(
            assert_commit_connector,
            &connector_d,
            &assert_commit_timeout_input_0,
            &connector_d_input,
        );
        assert_commit_timeout_txns.push(assert_commit_timeout_tx);
    }

    // take-2
    let take2 = Take2Transaction::new_for_validation(
        &connector_0,
        &connector_d,
        &connector_e,
        &connector_f,
        &guardian_connector,
        connector_0_input,
        connector_d_input,
        connector_e_input,
        connector_f_input,
        guardian_connector_input,
        &params.operator_receive_address,
    )
    .map_err(|e| anyhow::anyhow!("failed to create take-2 txn: {e}"))?;

    Ok(Bitvm2Graph {
        operator_pre_signed: false,
        committee_pre_signed: false,
        parameters: params,

        cur_prekickoff,
        next_prekickoff,
        force_skip_kickoff,
        quick_challenge,
        challenge_incomplete_kickoff,

        pegin,
        kickoff,
        take1,
        challenge,
        take2,

        watchtower_challenge_init,
        watchtower_challenge_timeout_txns,
        nack_txns,
        blockhash_commit_timeout,

        assert_init,
        assert_commit_timeout_txns,

        connector_e,
    })
}

pub fn operator_pre_sign(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Vec<Witness>> {
    let keypair_pubkey = PublicKey::from(operator_keypair.public_key());
    if keypair_pubkey != graph.parameters.operator_pubkey {
        bail!("operator keypair does not match graph operator pubkey".to_string())
    };

    let mut wits = vec![];
    let context = graph.parameters.get_operator_context(operator_keypair)?;
    let network = context.network;
    let operator_taproot_public_key = context.operator_taproot_public_key;

    // presign force_skip_kickoff
    let kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let next_force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    graph.force_skip_kickoff.pre_sign_and_push(
        &context,
        &kickoff_connector,
        &next_force_skip_connector,
    );
    wits.push(graph.force_skip_kickoff.tx().input[0].witness.clone());
    wits.push(graph.force_skip_kickoff.tx().input[1].witness.clone());

    // presign quick_challenge
    let guardian_connector = GuardianConnector::new(network, &operator_taproot_public_key);
    graph.quick_challenge.pre_sign_and_push(
        &context,
        &guardian_connector,
        &next_force_skip_connector,
    );
    wits.push(graph.quick_challenge.tx().input[0].witness.clone());
    wits.push(graph.quick_challenge.tx().input[1].witness.clone());

    // presign challenge_incomplete_kickoff
    let next_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    graph.challenge_incomplete_kickoff.pre_sign_and_push(
        &context,
        &guardian_connector,
        &next_prekickoff_connector,
    );
    wits.push(graph.challenge_incomplete_kickoff.tx().input[0].witness.clone());
    wits.push(graph.challenge_incomplete_kickoff.tx().input[1].witness.clone());

    graph.operator_pre_signed = true;
    Ok(wits)
}

pub fn push_operator_pre_signature(
    graph: &mut Bitvm2Graph,
    signed_witness: &[Witness],
) -> Result<()> {
    if graph.operator_pre_signed {
        bail!("already pre-signed by operator".to_string())
    };
    if signed_witness.len() != operator_presig_num() {
        bail!("invalid number of pre-signatures".to_string())
    };

    graph.force_skip_kickoff.tx_mut().input[0].witness = signed_witness[0].clone();
    graph.force_skip_kickoff.tx_mut().input[1].witness = signed_witness[1].clone();
    graph.quick_challenge.tx_mut().input[0].witness = signed_witness[2].clone();
    graph.quick_challenge.tx_mut().input[1].witness = signed_witness[3].clone();
    graph.challenge_incomplete_kickoff.tx_mut().input[0].witness = signed_witness[4].clone();
    graph.challenge_incomplete_kickoff.tx_mut().input[1].witness = signed_witness[5].clone();

    graph.operator_pre_signed = true;
    Ok(())
}

/// remember to sign replensish inputs (if any) after this
pub fn operator_sign_prekickoff_input_0(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let prev_prekickoff_connector = PrekickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.cur_prekickoff.sign_input_0(&operator_context, &prev_prekickoff_connector);
    Ok(graph.cur_prekickoff.tx().clone())
}

pub fn operator_sign_skip_kickoff(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    operator_receive_address: Address,
    fee_rate: f64,
) -> Result<Option<Transaction>> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let kickoff_connector = KickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    let kickoff_connector_input = Input {
        outpoint: OutPoint { txid: graph.cur_prekickoff.tx().compute_txid(), vout: 1 },
        amount: graph.cur_prekickoff.tx().output[1].value,
    };
    // create a sample tx to estimate fee
    let sample_tx = operator_skip_kickoff(
        &operator_context,
        &kickoff_connector,
        kickoff_connector_input.clone(),
        Amount::ZERO,
        operator_receive_address.clone(),
    )
    .map_err(|e| anyhow::anyhow!("failed to create sample skip-kickoff txn: {e}"))?;

    let fee_amount =
        Amount::from_sat((sample_tx.weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64);
    if fee_amount + Amount::from_sat(DUST_AMOUNT) >= kickoff_connector_input.amount {
        // if fee_amount > input_amount - dust_amount, skip-kickoff tx is meaningless
        return Ok(None);
    }
    match operator_skip_kickoff(
        &operator_context,
        &kickoff_connector,
        kickoff_connector_input,
        fee_amount,
        operator_receive_address,
    ) {
        Ok(tx) => Ok(Some(tx)),
        Err(e) => bail!("failed to create skip-kickoff txn: {e}"),
    }
}

pub fn operator_sign_kickoff(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let kickoff_connector = KickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.kickoff.sign_input_0(&operator_context, &kickoff_connector);
    Ok(graph.kickoff.tx().clone())
}

pub fn operator_sign_take1(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_a = ConnectorA::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_b =
        ConnectorB::new(operator_context.network, &operator_context.operator_taproot_public_key);
    let connector_c =
        ConnectorC::new(operator_context.network, &operator_context.operator_taproot_public_key);
    let guardian_connector = GuardianConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.take1.sign_input_1(&operator_context, &connector_a);
    graph.take1.sign_input_2(&operator_context, &connector_b);
    graph.take1.sign_input_3(&operator_context, &connector_c);
    graph.take1.sign_input_4(&operator_context, &guardian_connector);
    Ok(graph.take1.tx().clone())
}

pub fn operator_sign_take2(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_d = ConnectorD::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_f = ConnectorF::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let guardian_connector = GuardianConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.take2.sign_input_1(&operator_context, &connector_d);
    graph.take2.sign_input_2(&operator_context, &graph.connector_e);
    graph.take2.sign_input_3(&operator_context, &connector_f);
    graph.take2.sign_input_4(&operator_context, &guardian_connector);
    Ok(graph.take2.tx().clone())
}

pub fn operator_sign_watchtower_challenge_init(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_b =
        ConnectorB::new(operator_context.network, &operator_context.operator_taproot_public_key);
    graph.watchtower_challenge_init.sign_input_0(&operator_context, &connector_b);
    Ok(graph.watchtower_challenge_init.tx().clone())
}

pub fn operator_sign_watchtower_challenge_timeout(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    watchtower_index: usize,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    if watchtower_index >= graph.parameters.watchtower_pubkeys.len() {
        bail!("invalid watchtower index {watchtower_index}".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let watchtower_challenge_connector = WatchtowerChallengeConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &graph.parameters.watchtower_pubkeys[watchtower_index],
    );
    let ack_connector = AckConnector::new(
        operator_context.network,
        &operator_context.n_of_n_taproot_public_key,
        &graph.parameters.hashlocks[watchtower_index],
    );
    let watchtower_connectors = (watchtower_challenge_connector, ack_connector);
    graph.watchtower_challenge_timeout_txns[watchtower_index]
        .sign_input_0(&operator_context, &watchtower_connectors);
    Ok(graph.watchtower_challenge_timeout_txns[watchtower_index].tx().clone())
}

pub fn operator_sign_ack(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    watchtower_index: usize,
    preimage: &Vec<u8>,
) -> Result<(TxIn, Amount)> {
    if hash160(preimage) != graph.parameters.hashlocks[watchtower_index] {
        bail!("invalid preimage for watchtower index {watchtower_index}".to_string())
    };
    if watchtower_index >= graph.parameters.watchtower_pubkeys.len() {
        bail!("invalid watchtower index {watchtower_index}".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let watchtower_challenge_connector = WatchtowerChallengeConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &graph.parameters.watchtower_pubkeys[watchtower_index],
    );
    let ack_connector = AckConnector::new(
        operator_context.network,
        &operator_context.n_of_n_taproot_public_key,
        &graph.parameters.hashlocks[watchtower_index],
    );
    let watchtower_connectors = (watchtower_challenge_connector, ack_connector);
    let ack_vout = watchtower_index * 2 + 1;
    let ack_input = Input {
        outpoint: OutPoint {
            txid: graph.watchtower_challenge_init.tx().compute_txid(),
            vout: ack_vout as u32,
        },
        amount: graph.watchtower_challenge_init.tx().output[ack_vout].value,
    };
    match operator_ack(&watchtower_connectors, preimage, ack_input.clone()) {
        Ok(txin) => Ok((txin, ack_input.amount)),
        Err(e) => bail!("failed to sign ack for watchtower index {watchtower_index}: {e}"),
    }
}

pub fn operator_sign_blockhash_commit(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    latest_blockhash: &[u8; 32],
    wots_secret_key: &WinternitzSecret,
) -> Result<(TxIn, Amount)> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let blockhash_wots_pubkey = graph.parameters.operator_wots_pubkeys.0[0];
    if Wots32::generate_public_key(wots_secret_key) != blockhash_wots_pubkey {
        bail!("provided WOTS secret key does not match expected public key".to_string())
    };
    let connector_g = ConnectorG::new(
        operator_context.network,
        &operator_context.n_of_n_taproot_public_key,
        &operator_context.operator_taproot_public_key,
        &blockhash_wots_pubkey,
    );
    let connector_g_vout = 2 * graph.parameters.watchtower_pubkeys.len() as u64;
    let connector_g_input = Input {
        outpoint: OutPoint {
            txid: graph.watchtower_challenge_init.tx().compute_txid(),
            vout: connector_g_vout as u32,
        },
        amount: graph.watchtower_challenge_init.tx().output[connector_g_vout as usize].value,
    };
    match operator_commit_blockhash(
        &connector_g,
        latest_blockhash,
        wots_secret_key,
        connector_g_input.clone(),
    ) {
        Ok(txin) => Ok((txin, connector_g_input.amount)),
        Err(e) => bail!("failed to sign blockhash commit: {e}"),
    }
}

pub fn operator_sign_assert_init(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_c =
        ConnectorC::new(operator_context.network, &operator_context.operator_taproot_public_key);
    graph.assert_init.sign_input_0(&operator_context, &connector_c);
    Ok(graph.assert_init.tx().clone())
}

pub fn operator_sign_assert_commit(
    operator_keypair: Keypair,
    graph: &mut Bitvm2Graph,
    wots_secret_keys: &OperatorWotsSecretKeys,
    guest_inputs: GuestInputs,
    proof: Groth16Proof,
    groth16_pubin: PublicInputs,
    vk: &VerifyingKey,
) -> Result<Vec<(TxIn, Amount)>> {
    println!("operator_send_assert_commit start operator_sign_assert_commit");
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    if !is_valid_wots_secrets(wots_secret_keys, &graph.parameters.operator_wots_pubkeys) {
        bail!("provided WOTS secret keys do not match expected public keys".to_string())
    };
    let assert_commit_connectors = generate_mixed_chunked_assert_commit_connectors(
        operator_context.network,
        &operator_context.n_of_n_taproot_public_key,
        &graph.parameters.operator_wots_pubkeys,
    );
    let mut assert_commit_inputs = vec![];
    for i in 0..assert_commit_connectors.len() {
        let vout = i;
        let input = Input {
            outpoint: OutPoint { txid: graph.assert_init.tx().compute_txid(), vout: vout as u32 },
            amount: graph.assert_init.tx().output[vout].value,
        };
        assert_commit_inputs.push(input);
    }
    let proof_assertions = generate_assertions(proof, groth16_pubin, vk)
        .map_err(|e| anyhow::anyhow!("failed to generate assertions: {e}"))?;
    let txins = operator_commit_mixed_proof(
        &assert_commit_connectors,
        wots_secret_keys,
        &assert_commit_inputs,
        guest_inputs,
        proof_assertions,
    )?;
    Ok(txins
        .into_iter()
        .enumerate()
        .map(|(i, txin)| (txin, assert_commit_inputs[i].amount))
        .collect::<Vec<(TxIn, Amount)>>())
}

fn operator_commit_mixed_proof(
    assert_commit_connectors: &[AssertCommitConnector],
    wots_secret_keys: &OperatorWotsSecretKeys,
    assert_commit_inputs: &[Input],
    guest_inputs: GuestInputs,
    proof_assertions: bitvm::chunk::api::Assertions,
) -> Result<Vec<TxIn>> {
    if assert_commit_connectors.len() != assert_commit_inputs.len() {
        bail!("Mismatched number of AssertCommit connectors and inputs");
    }

    let (wots32_secret_keys, wots16_secret_keys) = mixed_assert_wots_secrets(wots_secret_keys);
    let mut wots32_values = Vec::with_capacity(1 + NUM_PUBS + NUM_U256);
    wots32_values.push(guest_inputs.genesis_sequencer_commit_txid);
    wots32_values.extend(proof_assertions.0);
    wots32_values.extend(proof_assertions.1);

    let mut wots16_values = Vec::with_capacity(1 + NUM_HASH);
    wots16_values.push(guest_inputs.graph_id);
    wots16_values.extend(proof_assertions.2);

    let mut res = vec![];
    let mut wots32_cursor = 0;
    let mut wots16_cursor = 0;
    for (i, acc) in assert_commit_connectors.iter().enumerate() {
        let chunk32_len = acc.wots32_pubkeys.len();
        let chunk16_len = acc.wots16_pubkeys.len();
        let input_0_leaf = 0;
        let mut txin = acc.generate_taproot_leaf_tx_in(input_0_leaf, &assert_commit_inputs[i]);

        let unlock_data = acc
            .generate_leaf_0_unlock_data(
                &wots32_secret_keys[wots32_cursor..wots32_cursor + chunk32_len].to_vec(),
                &wots16_secret_keys[wots16_cursor..wots16_cursor + chunk16_len].to_vec(),
                &wots32_values[wots32_cursor..wots32_cursor + chunk32_len].to_vec(),
                &wots16_values[wots16_cursor..wots16_cursor + chunk16_len].to_vec(),
            )
            .map_err(|e| anyhow::anyhow!("failed to sign mixed assert commit connector: {e}"))?;
        populate_taproot_txin_witness(
            &mut txin,
            &acc.generate_taproot_spend_info(),
            &acc.generate_taproot_leaf_script(0),
            unlock_data,
        );
        wots32_cursor += chunk32_len;
        wots16_cursor += chunk16_len;
        res.push(txin);
    }

    Ok(res)
}

pub fn is_valid_wots_secrets(
    wots_seckeys: &OperatorWotsSecretKeys,
    expected_pubkeys: &OperatorWotsPublicKeys,
) -> bool {
    // let generated_pubkeys = wots_secrets_to_pubkeys(wots_seckeys);
    // &generated_pubkeys == expected_pubkeys

    // Compare each generated WOTS public key against the expected public keys
    // without allocating large temporaries. This keeps stack usage small.
    let (guest_extra_expected, guest_assert_expected, proof_pubkeys_box) = expected_pubkeys;
    let proof_pubkeys = proof_pubkeys_box.as_ref();

    let mut idx: usize = 0;

    // guest_extra (Wots32)
    for expected in guest_extra_expected.iter() {
        let generated = Wots32::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    // guest_assert graph_id (Wots16)
    let generated = Wots16::generate_public_key(&wots_seckeys[idx]);
    if generated != guest_assert_expected.graph_id[0] {
        return false;
    }
    idx += 1;

    // guest_assert genesis txid (Wots32)
    let generated = Wots32::generate_public_key(&wots_seckeys[idx]);
    if generated != guest_assert_expected.genesis_sequencer_commit_txid[0] {
        return false;
    }
    idx += 1;

    // proof pubins (Wots32)
    for expected in proof_pubkeys.0.iter() {
        let generated = Wots32::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    // proof fq_arr (Wots32)
    for expected in proof_pubkeys.1.iter() {
        let generated = Wots32::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    // proof h_arr (Wots16)
    for expected in proof_pubkeys.2.iter() {
        let generated = Wots16::generate_public_key(&wots_seckeys[idx]);
        if &generated != expected {
            return false;
        }
        idx += 1;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn wrapper_challenge_guest_values_bind_vk_raw_graph_and_genesis() {
        let operator_vk_hash = [0x11u8; 32];
        let graph_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let genesis_txid = [0x33u8; 32];

        let values = wrapper_challenge_guest_values(operator_vk_hash, graph_id, genesis_txid);

        assert_eq!(values.operator_vk_hash, operator_vk_hash);
        assert_eq!(values.graph_id, *graph_id.as_bytes());
        assert_eq!(values.genesis_sequencer_commit_txid, genesis_txid);
        assert_eq!(
            values.public_values().to_vec(),
            [operator_vk_hash.as_slice(), graph_id.as_bytes(), genesis_txid.as_slice()].concat()
        );
    }

    #[test]
    fn operator_wots_guest_assert_keys_use_wots16_for_graph_id() {
        let (secrets, pubkeys) = generate_wots_keys("mixed-guest-wots");

        assert_eq!(Wots32::generate_public_key(&secrets[0]), pubkeys.0[0]);
        assert_eq!(Wots16::generate_public_key(&secrets[1]), pubkeys.1.graph_id[0]);
        assert_eq!(
            Wots32::generate_public_key(&secrets[2]),
            pubkeys.1.genesis_sequencer_commit_txid[0]
        );
    }

    #[test]
    fn wrapper_guest_validation_binds_raw_graph_id() {
        let (secrets, pubkeys) = generate_wots_keys("wrapper-guest-validation-raw-graph");
        let operator_vk_hash = [0x55u8; 32];
        let graph_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let genesis_txid = [0x77u8; 32];
        let values = wrapper_challenge_guest_values(operator_vk_hash, graph_id, genesis_txid);
        let lock_script = verify_wrapper_guest_pubin(
            &pubkeys.0[0],
            &pubkeys.1.graph_id[0],
            &pubkeys.1.genesis_sequencer_commit_txid[0],
            &pubkeys.2.0,
            &values,
            0,
        )[0]
        .clone();
        let pubin_commitment = values.public_values_commitment();

        let correct_script = script! {
            { Wots32::sign_to_raw_witness(&secrets[3 + GUEST_PUBIN_COMMITMENT_INDEX], &pubin_commitment) }
            { Wots32::sign_to_raw_witness(&secrets[0], &operator_vk_hash) }
            { Wots16::sign_to_raw_witness(&secrets[1], graph_id.as_bytes()) }
            { Wots32::sign_to_raw_witness(&secrets[2], &genesis_txid) }
            { lock_script.clone() }
        };
        let correct_result = execute_script_without_stack_limit(correct_script);
        assert!(!correct_result.success);
        assert_eq!(correct_result.final_stack.len(), 1);

        let mut wrong_graph_id = *graph_id.as_bytes();
        wrong_graph_id[0] ^= 0xff;
        let wrong_script = script! {
            { Wots32::sign_to_raw_witness(&secrets[3 + GUEST_PUBIN_COMMITMENT_INDEX], &pubin_commitment) }
            { Wots32::sign_to_raw_witness(&secrets[0], &operator_vk_hash) }
            { Wots16::sign_to_raw_witness(&secrets[1], &wrong_graph_id) }
            { Wots32::sign_to_raw_witness(&secrets[2], &genesis_txid) }
            { lock_script }
        };
        let wrong_result = execute_script_without_stack_limit(wrong_script);
        assert!(wrong_result.success);
        assert_eq!(wrong_result.final_stack.len(), 1);
    }
}

pub fn take1_timelock(network: Network) -> u32 {
    num_blocks_per_network(network, CONNECTOR_A_TIMELOCK)
}

/// take2 has two timelocks, relative to (watchtower_challenge_init, assert_init)
pub fn take2_timelocks(network: Network) -> (u32, u32) {
    (
        num_blocks_per_network(network, CONNECTOR_F_TIMELOCK)
            + if network == Network::Testnet { 24 } else { 0 } // Testnet extra delay
            + if network == Network::Testnet4 { 48 } else { 0 } // Testnet4 extra delay
            + if network == Network::Regtest { 6 } else { 0 }, // Regtest extra delay
        num_blocks_per_network(network, CONNECTOR_D_TIMELOCK)
            + if network == Network::Testnet { 6 } else { 0 } // Testnet extra delay
            + if network == Network::Testnet4 { 100 } else { 0 } // Testnet4 extra delay
            + if network == Network::Regtest { 6 } else { 0 }, // Regtest extra delay
    )
}

pub fn watchtower_challenge_timeout_timelock(network: Network) -> u32 {
    num_blocks_per_network(network, WATCHTOWER_CHALLENGE_TIMELOCK)
        + if network == Network::Testnet { 12 } else { 0 } // Testnet extra delay
        + if network == Network::Testnet4 { 20 } else { 0 } // Testnet4 extra delay
        + if network == Network::Regtest { 2 } else { 0 } // Regtest extra delay
}
