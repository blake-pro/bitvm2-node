//! Generate operator wrapper proof.
use clap::Parser;
use operator_wrapper_proof::{Args, OperatorWrapperProofBuilder, parse_hex_array};
use proof_builder::{ProofBuilder, ProofRequest};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    zkm_sdk::utils::setup_logger();

    let builder = OperatorWrapperProofBuilder::new();
    let ctx = ProofRequest::WrapperProofRequest {
        operator_proof_id: 0,
        operator_input_proof: args.operator_input_proof.clone(),
        graph_id: parse_hex_array::<16>(&args.graph_id).unwrap(),
        genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),
        output: args.output.clone(),
    };

    let (input, proof, cycles, _) = builder.build_proof(&ctx).unwrap();
    tracing::info!("Operator wrapper proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
