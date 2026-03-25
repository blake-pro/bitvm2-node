use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use proof_builder::{
    PartStarkVkAttestationAnchorRequest, PartStarkVkAttestationAnchorResponse,
    PartStarkVkAttestationRequest, PartStarkVkAttestationResponse, PartStarkVkAttestationSignature,
};
use reqwest::Client;
use sha2::{Digest, Sha256};
use zkm_verifier::Groth16Verifier;
use zkm_version::{
    PART_STARK_VK_ATTESTATION_DOMAIN_TAG, build_part_stark_vk_attestation_message,
    hash_part_stark_vk, parse_zkm_version,
};

const ATTESTATION_PATH: &str = "/v1/proofs/part_stark_vk_attestations";

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Opts {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Message {
        #[arg(long)]
        zkm_version: String,
    },
    Submit {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        zkm_version: String,
        #[arg(long)]
        sequencer_set_cosmos_block_height: i64,
        #[arg(long = "signer")]
        signer_pubkeys: Vec<String>,
        #[arg(long = "signature")]
        signatures: Vec<String>,
    },
    Anchor {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        batch_id: i64,
        #[arg(long)]
        bitcoin_txid: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.command {
        Command::Message { zkm_version } => print_message_payload(&zkm_version),
        Command::Submit {
            rpc_url,
            zkm_version,
            sequencer_set_cosmos_block_height,
            signer_pubkeys,
            signatures,
        } => {
            let response = submit_attestation(
                &rpc_url,
                &zkm_version,
                sequencer_set_cosmos_block_height,
                signer_pubkeys,
                signatures,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
        Command::Anchor { rpc_url, batch_id, bitcoin_txid } => {
            let response = bind_anchor(&rpc_url, batch_id, &bitcoin_txid).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
    }
}

fn print_message_payload(zkm_version: &str) -> anyhow::Result<()> {
    let normalized =
        parse_zkm_version(zkm_version).map_err(|e| anyhow!("invalid zkm_version: {e}"))?;
    let part_stark_vk = Groth16Verifier::get_part_stark_vk(&normalized);
    let message = build_part_stark_vk_attestation_message(
        PART_STARK_VK_ATTESTATION_DOMAIN_TAG,
        &normalized,
        &part_stark_vk,
    )
    .map_err(|e| anyhow!("failed to build attestation message: {e}"))?;
    let digest = Sha256::digest(&message);

    println!(
        "{}",
        serde_json::json!({
            "domain_tag": PART_STARK_VK_ATTESTATION_DOMAIN_TAG,
            "zkm_version": normalized,
            "part_stark_vk_hash": hash_part_stark_vk(&part_stark_vk),
            "message_hex": hex::encode(&message),
            "digest_hex": hex::encode(digest),
        })
    );
    Ok(())
}

async fn submit_attestation(
    rpc_url: &str,
    zkm_version: &str,
    sequencer_set_cosmos_block_height: i64,
    signer_pubkeys: Vec<String>,
    signatures: Vec<String>,
) -> anyhow::Result<PartStarkVkAttestationResponse> {
    if signer_pubkeys.len() != signatures.len() {
        return Err(anyhow!(
            "signer count mismatch: {} signer(s) but {} signature(s)",
            signer_pubkeys.len(),
            signatures.len()
        ));
    }
    let signatures = signer_pubkeys
        .into_iter()
        .zip(signatures)
        .map(|(signer_pubkey, signature)| PartStarkVkAttestationSignature {
            signer_pubkey,
            signature,
        })
        .collect();
    let request = PartStarkVkAttestationRequest {
        zkm_version: zkm_version.to_string(),
        sequencer_set_cosmos_block_height,
        signatures,
    };
    Client::new()
        .post(format!("{}{}", rpc_url.trim_end_matches('/'), ATTESTATION_PATH))
        .json(&request)
        .send()
        .await
        .context("failed to submit part_stark_vk attestation request")?
        .error_for_status()
        .context("part_stark_vk attestation submit returned error status")?
        .json::<PartStarkVkAttestationResponse>()
        .await
        .context("failed to decode part_stark_vk attestation response")
}

async fn bind_anchor(
    rpc_url: &str,
    batch_id: i64,
    bitcoin_txid: &str,
) -> anyhow::Result<PartStarkVkAttestationAnchorResponse> {
    Client::new()
        .post(format!(
            "{}{}/{}{}",
            rpc_url.trim_end_matches('/'),
            ATTESTATION_PATH,
            batch_id,
            "/bitcoin_anchor"
        ))
        .json(&PartStarkVkAttestationAnchorRequest { bitcoin_txid: bitcoin_txid.to_string() })
        .send()
        .await
        .context("failed to submit bitcoin anchor bind request")?
        .error_for_status()
        .context("bitcoin anchor bind returned error status")?
        .json::<PartStarkVkAttestationAnchorResponse>()
        .await
        .context("failed to decode bitcoin anchor bind response")
}
