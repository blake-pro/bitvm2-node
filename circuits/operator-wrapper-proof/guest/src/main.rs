#![no_main]
zkm_zkvm::entrypoint!(main);

use bitcoin_light_client_circuit::{
    decode_operator_public_outputs, hash_operator_constant, zkm_vk_hash_to_raw,
};
use verifier::verify_groth16_proof;

pub fn main() {
    let operator_proof: Vec<u8> = zkm_zkvm::io::read();
    let operator_public_values: Vec<u8> = zkm_zkvm::io::read();
    let operator_vk_hash: Vec<u8> = zkm_zkvm::io::read();
    let operator_zkm_version: String = zkm_zkvm::io::read();
    let graph_id: [u8; 16] = zkm_zkvm::io::read();
    let genesis_sequencer_commit_txid: [u8; 32] = zkm_zkvm::io::read();

    verify_groth16_proof(
        &operator_proof,
        &operator_public_values,
        &operator_vk_hash,
        &operator_zkm_version,
    )
    .expect("Failed to verify operator proof");

    let expected_constant = hash_operator_constant(graph_id, genesis_sequencer_commit_txid);
    let operator_vk_hash_raw =
        zkm_vk_hash_to_raw(&operator_vk_hash).expect("Invalid operator vk hash");
    let operator_outputs = decode_operator_public_outputs(
        &operator_public_values,
        operator_vk_hash_raw,
    )
    .expect("Invalid operator public values");
    assert_eq!(operator_outputs.constant, expected_constant);
    assert_eq!(operator_outputs.operator_vk_hash, operator_vk_hash_raw);

    zkm_zkvm::io::commit(&operator_vk_hash_raw);
    zkm_zkvm::io::commit(&graph_id);
    zkm_zkvm::io::commit(&genesis_sequencer_commit_txid);
}
