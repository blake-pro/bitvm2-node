//! Generate operator wrapper proof.
use anyhow::{Context, ensure};
use bitcoin::{Txid, hashes::Hash};
use bitcoin_light_client_circuit::{
    OperatorPublicOutputs, decode_operator_public_outputs, hash_operator_constant,
    zkm_vk_hash_to_raw,
};
use clap::Parser;
use proof_builder::{LongRunning, ProofBuilder, ProofRequest};
use sha2::{Digest, Sha256};
use std::fs;
use std::str::FromStr;
use std::sync::OnceLock;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};

static ELF_ID: OnceLock<String> = OnceLock::new();
const OPERATOR_WRAPPER: &[u8] = include_elf!("guest");

#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[serde(default)]
    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[serde(default)]
    #[clap(long, env, default_value = "")]
    pub operator_input_proof: String,

    #[serde(default)]
    #[clap(long, env, default_value = "")]
    pub graph_id: String,

    #[serde(default)]
    #[clap(long, env, default_value = "")]
    pub genesis_sequencer_commit_txid: String,

    #[serde(default)]
    #[clap(long, env, default_value = "wrapper-proof.bin")]
    pub output: String,

    #[serde(default = "default_scan_interval")]
    #[arg(long, default_value_t = 30)]
    pub scan_interval: u64,
}

fn default_scan_interval() -> u64 {
    30
}

impl Default for Args {
    fn default() -> Self {
        Self {
            enable: false,
            operator_input_proof: String::new(),
            graph_id: String::new(),
            genesis_sequencer_commit_txid: String::new(),
            output: "wrapper-proof.bin".to_string(),
            scan_interval: 30,
        }
    }
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        self.clone()
    }
}

#[derive(Clone, Debug)]
pub struct OperatorProofInputs {
    pub proof_bytes: Vec<u8>,
    pub public_values: Vec<u8>,
    pub vk_hash: Vec<u8>,
    pub vk_hash_raw: [u8; 32],
    pub zkm_version: String,
    pub outputs: OperatorPublicOutputs,
}

pub struct OperatorWrapperProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
}

impl OperatorWrapperProofBuilder {
    pub fn new() -> Self {
        let client = ProverClient::new();
        let (proving_key, verifying_key) = client.setup(OPERATOR_WRAPPER);
        Self { client, proving_key, verifying_key }
    }
}

pub fn parse_hex_array<const N: usize>(value: &str) -> anyhow::Result<[u8; N]> {
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .with_context(|| format!("failed to decode {N}-byte hex value"))?;
    ensure!(bytes.len() == N, "expected {N} bytes, got {}", bytes.len());
    Ok(bytes.try_into().expect("length already checked"))
}

pub fn read_operator_proof_inputs(path: &str) -> anyhow::Result<OperatorProofInputs> {
    let proof_file =
        fs::read(path).with_context(|| format!("failed to read operator proof '{path}'"))?;
    let public_values_path = format!("{path}.public_inputs.bin");
    let public_values = fs::read(&public_values_path)
        .with_context(|| format!("failed to read operator public inputs '{public_values_path}'"))?;
    let vk_hash_path = format!("{path}.vk_hash.bin");
    let vk_hash = fs::read(&vk_hash_path)
        .with_context(|| format!("failed to read operator vk hash '{vk_hash_path}'"))?;
    let zkm_version_path = format!("{path}.zkm_version.bin");
    let zkm_version = fs::read(&zkm_version_path)
        .with_context(|| format!("failed to read operator zkm version '{zkm_version_path}'"))
        .and_then(|raw| {
            String::from_utf8(raw).with_context(|| format!("invalid UTF-8 in '{zkm_version_path}'"))
        })?;

    let proof_bytes =
        if let Ok(proof) = bincode::deserialize::<ZKMProofWithPublicValues>(&proof_file) {
            ensure!(
                proof.public_values.to_vec() == public_values,
                "operator proof public values do not match sidecar"
            );
            ensure!(
                proof.zkm_version == zkm_version,
                "operator proof zkm_version does not match sidecar"
            );
            proof.bytes()
        } else {
            proof_file
        };

    let raw_vk_hash = zkm_vk_hash_to_raw(&vk_hash).map_err(anyhow::Error::msg)?;
    let outputs =
        decode_operator_public_outputs(&public_values, raw_vk_hash).map_err(anyhow::Error::msg)?;
    let vk_hash_raw = validate_operator_vk_hash_binding(&outputs, &vk_hash)?;

    Ok(OperatorProofInputs {
        proof_bytes,
        public_values,
        vk_hash,
        vk_hash_raw,
        zkm_version,
        outputs,
    })
}

pub fn validate_operator_vk_hash_binding(
    outputs: &OperatorPublicOutputs,
    vk_hash: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let raw_vk_hash = zkm_vk_hash_to_raw(vk_hash).map_err(anyhow::Error::msg)?;
    ensure!(
        outputs.operator_vk_hash == raw_vk_hash,
        "operator vk hash does not match authenticated operator public output"
    );
    Ok(raw_vk_hash)
}

impl ProofBuilder for OperatorWrapperProofBuilder {
    fn client(&self) -> &zkm_sdk::ProverClient {
        &self.client
    }

    fn pk(&self) -> &zkm_sdk::ZKMProvingKey {
        &self.proving_key
    }

    fn vk(&self) -> &zkm_sdk::ZKMVerifyingKey {
        &self.verifying_key
    }

    fn name() -> String {
        "operator-wrapper".to_string()
    }

    #[tracing::instrument(level = "info", skip(self, ctx))]
    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::WrapperProofRequest {
            operator_input_proof,
            graph_id,
            genesis_sequencer_commit_txid,
            ..
        } = ctx
        else {
            anyhow::bail!("Invalid proof request type");
        };

        let operator_inputs = read_operator_proof_inputs(operator_input_proof)?;
        let genesis_txid = Txid::from_str(genesis_sequencer_commit_txid)
            .with_context(|| format!("invalid genesis txid '{genesis_sequencer_commit_txid}'"))?;
        let genesis_txid_bytes = genesis_txid.to_byte_array();
        let expected_constant = hash_operator_constant(*graph_id, genesis_txid_bytes);
        ensure!(
            operator_inputs.outputs.constant == expected_constant,
            "operator public constant does not match wrapper session"
        );
        let (proof, cycles, proving_time) = tracing::info_span!("generate wrapper proof")
            .in_scope(|| -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&operator_inputs.proof_bytes);
                stdin.write(&operator_inputs.public_values);
                stdin.write(&operator_inputs.vk_hash);
                stdin.write(&operator_inputs.zkm_version);
                stdin.write(graph_id);
                stdin.write(&genesis_txid_bytes);

                let elf_id = if ELF_ID.get().is_none() {
                    ELF_ID
                        .set(hex::encode(Sha256::digest(&self.proving_key.elf)))
                        .map_err(anyhow::Error::msg)?;
                    None
                } else {
                    Some(ELF_ID.get().unwrap().clone())
                };
                tracing::info!("elf id: {:?}", elf_id);

                let proving_start = tokio::time::Instant::now();
                let (proof, cycles) = self.client.prove_with_cycles(
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Groth16,
                    elf_id,
                )?;
                let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                Ok((proof, cycles, proving_duration))
            })?;

        Ok((vec![], proof, cycles, proving_time))
    }

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        _input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::WrapperProofRequest { output, .. } = ctx else {
            anyhow::bail!("invalid context");
        };
        let public_value_hex = hex::encode(proof.public_values.to_vec());
        let serialized_proof = bincode::serialize(&proof)?;
        let proof_size = serialized_proof.len();
        let zkm_version = proof.zkm_version.clone();
        fs::write(format!("{output}.public_inputs.bin"), proof.public_values.to_vec())?;
        fs::write(format!("{output}.vk_hash.bin"), self.verifying_key.bytes32())?;
        fs::write(format!("{output}.zkm_version.bin"), zkm_version)?;
        fs::write(output, serialized_proof)?;
        Ok((public_value_hex, proof_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_light_client_circuit::zkm_vk_hash_from_raw;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct LegacyOperatorPublicOutputs {
        btc_best_block_hash: [u8; 32],
        constant: [u8; 32],
        included_watchtowers: [u8; 32],
    }

    #[test]
    fn decode_operator_public_outputs_accepts_legacy_public_values() {
        let actual_vk_hash = [4u8; 32];
        let legacy_outputs = LegacyOperatorPublicOutputs {
            btc_best_block_hash: [0u8; 32],
            constant: [1u8; 32],
            included_watchtowers: [2u8; 32],
        };
        let public_values = bincode::serialize(&legacy_outputs).unwrap();

        let outputs = decode_operator_public_outputs(&public_values, actual_vk_hash).unwrap();

        assert_eq!(outputs.btc_best_block_hash, legacy_outputs.btc_best_block_hash);
        assert_eq!(outputs.constant, legacy_outputs.constant);
        assert_eq!(outputs.included_watchtowers, legacy_outputs.included_watchtowers);
        assert_eq!(outputs.operator_vk_hash, actual_vk_hash);
    }

    #[test]
    fn validate_operator_vk_hash_binding_rejects_mismatched_sidecar() {
        let outputs = OperatorPublicOutputs {
            btc_best_block_hash: [0u8; 32],
            constant: [1u8; 32],
            included_watchtowers: [2u8; 32],
            operator_vk_hash: [3u8; 32],
        };
        let mismatched = zkm_vk_hash_from_raw(&[4u8; 32]);

        let err = validate_operator_vk_hash_binding(&outputs, &mismatched).unwrap_err();

        assert!(err.to_string().contains("operator vk hash does not match"));
    }
}
