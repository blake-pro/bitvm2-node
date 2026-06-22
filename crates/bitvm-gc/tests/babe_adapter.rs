use ark_bn254::Fr;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::Groth16;
use bitvm_gc::babe_adapter::{
    BABE_M_CC, BabeBundleBuilder, build_assert_witness, build_real_setup_package,
    build_setup_package, derive_finalized_indices, extract_gc_circuit_data,
    open_real_setup_and_solder, verify_real_setup,
};
use bitvm_gc::operator::generate_assert_wots_key;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::collections::HashSet;
use std::str::FromStr;
use verifiable_circuit_babe::babe::DummyMulCircuit;

fn verifier_pubkey() -> bitcoin::PublicKey {
    bitcoin::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .expect("public key")
}

#[test]
#[ignore = "requires FGC/SGC original and compact runtime assets"]
fn real_setup_restores_private_state_and_verifies_soldering_proof() {
    let mut rng = ChaCha12Rng::seed_from_u64(42);
    let a = Fr::from(3_u64);
    let b = Fr::from(7_u64);
    let (_, vk) = Groth16::<ark_bn254::Bn254>::setup(
        DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng,
    )
    .expect("groth16 setup");
    let static_input = a * b;

    let (package, private_state) =
        build_real_setup_package(BABE_M_CC, &vk, static_input).expect("real setup");
    let restored =
        serde_json::from_slice(&serde_json::to_vec(&private_state).expect("serialize state"))
            .expect("deserialize state");
    let soldering_builder = BabeBundleBuilder::new();
    let finalized_indices = (0..BABE_M_CC).collect::<Vec<_>>();
    let (opened, finalized, soldering) = open_real_setup_and_solder(
        &soldering_builder,
        &restored,
        &package,
        &finalized_indices,
        &vk,
        static_input,
    )
    .expect("open real setup");

    verify_real_setup(
        &soldering_builder,
        &package,
        &opened,
        &finalized,
        &soldering,
        &vk,
        static_input,
    )
    .expect("verify soldering proof");

    let epk = &package.commits[finalized[0].index].epk;
    let h_msgs = finalized.iter().map(|data| package.commits[data.index].h_msg).collect::<Vec<_>>();
    extract_gc_circuit_data(verifier_pubkey(), epk, &h_msgs).expect("extract graph data");
}

#[test]
fn setup_payload_round_trips_and_derives_gc_data() {
    let package = build_setup_package(BABE_M_CC).expect("setup package");
    let encoded = serde_json::to_vec(&package).expect("serialize package");
    let decoded = serde_json::from_slice(&encoded).expect("deserialize package");
    assert_eq!(decoded, package);

    let finalized = derive_finalized_indices(&decoded, BABE_M_CC).expect("derive finalized");
    assert_eq!(finalized.iter().copied().collect::<HashSet<_>>().len(), BABE_M_CC);

    let h_msgs = finalized.iter().map(|index| decoded.commits[*index].h_msg).collect::<Vec<_>>();
    let gc_data =
        extract_gc_circuit_data(verifier_pubkey(), &decoded.commits[finalized[0]].epk, &h_msgs)
            .expect("extract gc data");

    assert_eq!(gc_data.final_msg_hashlocks, h_msgs);
    assert_eq!(gc_data.wire_hashes.len(), bitvm_gc::assert_scripts::INPUT_WIRE_NUM);
}

#[test]
fn assert_witness_binds_dynamic_input() {
    let (secret_key, _) = generate_assert_wots_key("graph-scoped-key");
    let proof = ark_groth16::Proof::<ark_bn254::Bn254> {
        a: ark_bn254::G1Affine::new(ark_bn254::Fq::from(1_u64), ark_bn254::Fq::from(2_u64)),
        ..Default::default()
    };
    let dynamic_input = Fr::from(9_u64);

    let witness = build_assert_witness(&proof, &secret_key, dynamic_input).expect("assert witness");
    let (_, recovered) = witness.recover_pi1_xd_without_verify().expect("recover witness");

    assert_eq!(recovered, dynamic_input);
}
