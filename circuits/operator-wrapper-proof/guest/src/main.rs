#![no_main]
zkm_zkvm::entrypoint!(main);

use bitcoin_light_client_circuit::{OperatorPublicOutputs, hash_operator_constant};
use verifier::verify_groth16_proof;
use zkm_primitives::io::ZKMPublicValues;

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

    let operator_outputs: OperatorPublicOutputs =
        ZKMPublicValues::from(&operator_public_values).read();
    let expected_constant = hash_operator_constant(graph_id, genesis_sequencer_commit_txid);
    assert_eq!(operator_outputs.constant, expected_constant);

    zkm_zkvm::io::commit(&operator_vk_hash);
    zkm_zkvm::io::commit(&graph_id);
    zkm_zkvm::io::commit(&genesis_sequencer_commit_txid);
}
