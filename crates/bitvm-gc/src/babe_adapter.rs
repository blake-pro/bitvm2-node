use rayon::prelude::*;
use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use anyhow::{Result, bail};
use ark_bn254::{Bn254, Fq, Fr};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use garbled_snark_verifier::bag::S;
use goat::assert_scripts::{
    INPUT_WIRE_NUM, OperatorAssertPublicKey, OperatorAssertSecretKey, WireHash, label_hash,
};
use goat::wots::{Wots, Wots96};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soldering_host::BabeBundle;
pub use soldering_host::BabeBundleBuilder;
use verifiable_circuit_babe::babe::{
    BabeBtcSig, ProverSetupState, WeKnownPi1SetupCt as RealSetupCt,
    babe_prover_wrongly_challenged_cac, babe_verifier_presign, build_challenge_assert_witness,
    interleave_dummy_positions,
};
use verifiable_circuit_babe::cac::{
    CACSetupPackage as RealCACSetupPackage, FinalizedInstanceData as RealFinalizedInstanceData,
    cac_finalize_indices,
};
use verifiable_circuit_babe::dre::N;
use verifiable_circuit_babe::gc::{
    SGC_PART1_CONSTANT_SIZE, SparseAdaptorEntry as RealSparseAdaptorEntry,
    SparseAdaptorRow as RealSparseAdaptorRow, SparseAdaptorTable as RealSparseAdaptorTable,
};
use verifiable_circuit_babe::instance::CACInstance;
use verifiable_circuit_babe::instance::commit::CACInstanceCommit as RealCACInstanceCommit;
use verifiable_circuit_babe::soldering::{
    SolderingData as RealSolderingData, SolderingProof as RealSolderingProof,
};
use verifiable_circuit_babe::transactions::{
    TxAssertWitness as RealTxAssertWitness,
    TxChallengeAssertWitness as RealTxChallengeAssertWitness,
};
use verifiable_circuit_babe::utils::pi1_xd_to_wots96_msg;
use verifiable_circuit_babe::verifier::{BABEVerifier, InstanceLightSecrets};

use crate::types::BitvmGcCircuitData;

/// Number of Wots96 digit signatures expected by the GOAT GC-V2 connector.
pub const WOTS_SIG_COUNT: usize = Wots96::TOTAL_DIGIT_LEN as usize;
pub const BABE_N_CC: usize = 181;
// TODO: use verifiable_circuit_babe::babe::M_CC instead
pub const BABE_M_CC: usize = 7;

pub type OpenedInstanceSeeds = Vec<(usize, u64)>;
pub type FinalizedInstances = Vec<FinalizedInstanceData>;
pub type SetupAndSolderingData = (OpenedInstanceSeeds, FinalizedInstances, SolderingData);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACSetupPackage {
    pub commits: Vec<CACInstanceCommit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACInstanceCommit {
    pub epk: Vec<[[u8; 20]; 2]>,
    pub constant_commits_0: [[[u8; 32]; 2]; 2],
    pub constant_commits_1: Vec<[[u8; 32]; 2]>,
    pub b_blind_commit: [u8; 32],
    pub h_msg: [u8; 20],
    pub h_ct_setup: [u8; 32],
    pub com_adaptor: [[u8; 32]; 2],
    pub com_gc: [[u8; 32]; 3],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedInstanceData {
    pub index: usize,
    pub final_msg_hash: [u8; 20],
    pub wire_hashes: Vec<WireHash>,
    pub real_data: Option<RealFinalizedPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFinalizedPayload {
    pub ciphertext_sets: [Vec<Option<[u8; 16]>>; 3],
    pub adaptor_tables: [SerializableSparseAdaptorTable; 2],
    pub ct_setup: SerializableSetupCt,
    pub constant_labels_0: [[u8; 16]; 2],
    pub constant_labels_1: Vec<[u8; 16]>,
    pub b: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactFinalizedInstanceData {
    pub index: usize,
    pub real_data: RealFinalizedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactSolderingData {
    pub finalized_indices: Vec<usize>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactSolderingProofPayload {
    pub opened: OpenedInstanceSeeds,
    pub finalized: Vec<CompactFinalizedInstanceData>,
    pub soldering: CompactSolderingData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableSetupCt {
    pub ct2_r_delta_g2: Vec<u8>,
    pub ct3_masked_msg: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableSparseAdaptorTable {
    pub entries: Vec<SerializableSparseAdaptorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableSparseAdaptorEntry {
    pub x: SerializableSparseAdaptorRow,
    pub y: SerializableSparseAdaptorRow,
    pub z: SerializableSparseAdaptorRow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableSparseAdaptorRow {
    pub cts: Vec<[u8; 32]>,
    pub offset: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolderingData {
    pub finalized_indices: Vec<usize>,
    pub soldered_output: SolderedLabelsData,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SolderedLabelsData {
    pub base_commitment: Vec<([u8; 32], [u8; 32])>,
    pub deltas: Vec<Vec<([u8; 16], [u8; 16])>>,
    pub commitments: Vec<Vec<([u8; 32], [u8; 32])>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BabeVerifierPrivateState {
    pub instance_seeds: Vec<u64>,
    pub light_secrets: Vec<InstanceLightSecrets>,
    pub statement_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeVerifierState {
    pub package: CACSetupPackage,
    pub finalized_indices: Vec<usize>,
    pub verifier_pubkey: bitcoin::PublicKey,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeProverState {
    pub package: CACSetupPackage,
    pub finalized: Vec<FinalizedInstanceData>,
    pub soldering: SolderingData,
    pub h_msgs: Vec<[u8; 20]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxAssertWitness {
    pub wots_sig: Vec<[u8; 21]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeChallengeAssertWitness {
    pub verifier_index: usize,
    pub witness: SerializableChallengeAssertWitness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableChallengeAssertWitness {
    pub input_labels: Vec<[u8; 16]>,
    pub wots_sig: Vec<[u8; 21]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeWronglyChallengedWitness {
    pub verifier_index: usize,
    pub final_msg: Vec<u8>,
}

impl CACInstanceCommit {
    /// Builds deterministic placeholder setup commitments for tests and wiring.
    pub fn sample(seed: u8) -> Self {
        let epk = (0..3 * N)
            .map(|wire| [hash20(&[seed, wire as u8, 0]), hash20(&[seed, wire as u8, 1])])
            .collect();
        Self {
            epk,
            constant_commits_0: [
                [hash32(&[seed, 0xf0, 0]), hash32(&[seed, 0xf0, 1])],
                [hash32(&[seed, 0xf1, 0]), hash32(&[seed, 0xf1, 1])],
            ],
            constant_commits_1: (0..SGC_PART1_CONSTANT_SIZE)
                .map(|wire| [hash32(&[seed, wire as u8, 0]), hash32(&[seed, wire as u8, 1])])
                .collect(),
            b_blind_commit: hash32(&[seed, 0x9f]),
            h_msg: hash20(&[seed, 0xa0]),
            h_ct_setup: hash32(&[seed, 0xa1]),
            com_adaptor: [hash32(&[seed, 0xa2]), hash32(&[seed, 0xa3])],
            com_gc: [hash32(&[seed, 0xa4]), hash32(&[seed, 0xa5]), hash32(&[seed, 0xa6])],
        }
    }
}

impl FinalizedInstanceData {
    /// Builds deterministic placeholder finalized data for tests and graph wiring.
    pub fn sample(index: usize) -> Self {
        let seed = index as u8;
        let wire_hashes = (0..INPUT_WIRE_NUM)
            .map(|wire| WireHash {
                true_label_hash: hash20(&[seed, wire as u8, 1]),
                false_label_hash: hash20(&[seed, wire as u8, 0]),
            })
            .collect();
        Self { index, final_msg_hash: hash20(&[seed, 0xb0]), wire_hashes, real_data: None }
    }
}

impl CompactFinalizedInstanceData {
    pub fn try_from_finalized(finalized: &FinalizedInstanceData) -> Result<Self> {
        let real_data = finalized.real_data.clone().ok_or_else(|| {
            anyhow::anyhow!("finalized index {} lacks real BABE payload", finalized.index)
        })?;
        Ok(Self { index: finalized.index, real_data })
    }
}

impl SolderingData {
    /// Builds deterministic placeholder soldering data for the selected finalized indices.
    pub fn sample(finalized_indices: Vec<usize>) -> Self {
        Self { finalized_indices, soldered_output: SolderedLabelsData::default(), proof: vec![] }
    }
}

/// Builds a deterministic placeholder CAC setup package with `n_cc` instances.
pub fn build_setup_package(n_cc: usize) -> Result<CACSetupPackage> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    Ok(CACSetupPackage {
        commits: (0..n_cc).map(|index| CACInstanceCommit::sample(index as u8)).collect(),
    })
}

/// Builds a real random BABE/CAC setup package bound to the supplied Groth16 statement.
pub fn build_real_setup_package(
    n_cc: usize,
    vk: &Groth16VerifyingKey<Bn254>,
    static_input: Fr,
) -> Result<(CACSetupPackage, BabeVerifierPrivateState)> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    ensure_real_gc_assets_configured()?;
    let seeds = (0..n_cc).map(|_| rand::random()).collect::<Vec<u64>>();
    let generated = catch_unwind(AssertUnwindSafe(|| {
        seeds
            .par_iter()
            .map(|seed| {
                let (commit, secrets) = CACInstance::commit_from_seed(*seed, vk, static_input)
                    .map_err(anyhow::Error::msg)?;
                Ok((
                    commit,
                    InstanceLightSecrets {
                        delta: secrets.delta,
                        encoding_keys: secrets.input_0labels,
                    },
                ))
            })
            .collect::<Result<Vec<_>>>()
    }))
    .map_err(|_| anyhow::anyhow!("real BABE verifier setup panicked while loading GC assets"))??;
    let (commits, light_secrets): (Vec<_>, Vec<_>) = generated.into_iter().unzip();
    let package = from_real_package(&RealCACSetupPackage { commits });
    let private_state = BabeVerifierPrivateState {
        instance_seeds: seeds,
        light_secrets,
        statement_digest: statement_digest(vk, static_input)?,
    };

    Ok((package, private_state))
}

/// Reconstructs the real Verifier instances and creates CAC opening/soldering output data.
pub fn open_real_setup_and_solder(
    soldering_builder: &BabeBundleBuilder,
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    static_input: Fr,
) -> Result<SetupAndSolderingData> {
    ensure_real_gc_assets_configured()?;
    if private_state.statement_digest != statement_digest(vk, static_input)? {
        bail!("BABE setup statement does not match persisted verifier state");
    }
    validate_finalized_indices(package, finalized_indices)?;
    let verifier = restore_real_verifier(private_state, package, vk, static_input)?;
    if from_real_package(&verifier.commit()) != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }
    let bundle = soldering_builder
        .babe_verifier_open_and_solder(&verifier, finalized_indices)
        .map_err(anyhow::Error::msg)?;
    Ok((
        bundle.opened,
        bundle
            .finalized
            .iter()
            .map(|data| from_real_finalized(data, package))
            .collect::<Result<Vec<_>>>()?,
        from_real_soldering(&bundle.soldering)?,
    ))
}

/// Verifies real CAC openings, commitments, and the native Ziren soldering proof.
pub fn verify_real_setup(
    soldering_builder: &BabeBundleBuilder,
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
    vk: &Groth16VerifyingKey<Bn254>,
    static_input: Fr,
) -> Result<()> {
    let real_package = to_real_package(package);
    let real_finalized = finalized
        .iter()
        .map(to_real_finalized)
        .collect::<Result<Vec<RealFinalizedInstanceData>>>()?;

    let bundle = BabeBundle {
        opened: opened.to_vec(),
        finalized: real_finalized,
        soldering: to_real_soldering(soldering)?,
    };
    soldering_builder
        .babe_prover_verify_setup(&real_package, &bundle, vk, static_input)
        .map_err(anyhow::Error::msg)
}

/// Removes setup-derived public fields from the Verifier-to-Operator soldering proof payload.
pub fn compact_soldering_proof_payload(
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<CompactSolderingProofPayload> {
    Ok(CompactSolderingProofPayload {
        opened: opened.to_vec(),
        finalized: finalized
            .iter()
            .map(CompactFinalizedInstanceData::try_from_finalized)
            .collect::<Result<Vec<_>>>()?,
        soldering: CompactSolderingData {
            finalized_indices: soldering.finalized_indices.clone(),
            proof: soldering.proof.clone(),
        },
    })
}

/// Reconstructs the full BABE setup data using the locally trusted setup package.
pub fn expand_compact_soldering_proof_payload(
    package: &CACSetupPackage,
    payload: CompactSolderingProofPayload,
) -> Result<SetupAndSolderingData> {
    let finalized = payload
        .finalized
        .into_iter()
        .map(|data| expand_compact_finalized_instance(package, data))
        .collect::<Result<Vec<_>>>()?;
    Ok((payload.opened, finalized, expand_compact_soldering_data(payload.soldering)?))
}

/// Derives finalized circuit indices using the real BABE/CAC Fiat-Shamir selection.
pub fn derive_finalized_indices(package: &CACSetupPackage, m_cc: usize) -> Result<Vec<usize>> {
    let n_cc = package.commits.len();
    if m_cc == 0 || m_cc > n_cc {
        bail!("invalid m_cc {m_cc} for n_cc {n_cc}");
    }
    Ok(cac_finalize_indices(package.commits.len(), m_cc))
}

/// Opens non-finalized placeholder instances and returns finalized data plus soldering data.
pub fn open_and_solder(
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> Result<SetupAndSolderingData> {
    let finalized_set = finalized_indices.iter().copied().collect::<HashSet<_>>();
    if finalized_set.len() != finalized_indices.len() {
        bail!("duplicate finalized index");
    }
    if finalized_indices.iter().any(|index| *index >= package.commits.len()) {
        bail!("finalized index out of range");
    }
    let opened = (0..package.commits.len())
        .filter(|index| !finalized_set.contains(index))
        .map(|index| (index, deterministic_seed(index)))
        .collect::<Vec<_>>();
    let finalized =
        finalized_indices.iter().map(|index| FinalizedInstanceData::sample(*index)).collect();
    let soldering = SolderingData::sample(finalized_indices.to_vec());
    Ok((opened, finalized, soldering))
}

/// Validates placeholder opened, finalized, and soldering data consistency.
pub fn verify_setup(
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<()> {
    let n_cc = package.commits.len();
    let finalized_set = finalized.iter().map(|data| data.index).collect::<HashSet<_>>();
    if finalized_set.len() != finalized.len() {
        bail!("duplicate finalized data");
    }
    for (index, seed) in opened {
        if *index >= n_cc {
            bail!("opened index {index} out of range");
        }
        if finalized_set.contains(index) {
            bail!("index {index} cannot be both opened and finalized");
        }
        if *seed != deterministic_seed(*index) {
            bail!("opened seed mismatch for index {index}");
        }
    }
    if soldering.finalized_indices != finalized.iter().map(|data| data.index).collect::<Vec<_>>() {
        bail!("soldering finalized indices mismatch");
    }
    for data in finalized {
        if data.index >= n_cc {
            bail!("finalized index {} out of range", data.index);
        }
        if data.wire_hashes.len() != INPUT_WIRE_NUM {
            bail!("finalized index {} has invalid wire hash count", data.index);
        }
    }
    Ok(())
}

/// Extracts one graph slot owned by `verifier_pubkey` from finalized setup data.
pub fn extract_gc_circuit_data(
    verifier_pubkey: bitcoin::PublicKey,
    epk: &[[[u8; 20]; 2]],
    h_msgs: &[[u8; 20]],
) -> Result<BitvmGcCircuitData> {
    if h_msgs.len() != BABE_M_CC {
        bail!("each verifier must contribute exactly {BABE_M_CC} finalized BABE instances");
    }
    if epk.len() != 3 * N {
        bail!("BABE input commitment count {} is incompatible with 3 * {N}", epk.len());
    }

    let dummy = padding_wire_hashes()[0];
    let padded = interleave_dummy_positions(&epk[..N], &epk[N..2 * N], &epk[2 * N..], dummy);
    let wire_hashes: [WireHash; INPUT_WIRE_NUM] = padded
        .iter()
        .map(to_wire_hash)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|hashes: Vec<WireHash>| {
            anyhow::anyhow!(
                "BABE input commitment count {} is incompatible with GOAT connector wire count {INPUT_WIRE_NUM}",
                hashes.len()
            )
        })?;

    Ok(BitvmGcCircuitData { verifier_pubkey, final_msg_hashlocks: h_msgs.to_vec(), wire_hashes })
}

pub fn build_assert_witness(
    proof: &ark_groth16::Proof<Bn254>,
    assert_secret_key: &OperatorAssertSecretKey,
    dynamic_input: Fr,
) -> Result<TxAssertWitness> {
    if assert_secret_key.is_empty() {
        bail!("operator WOTS secret key must not be empty");
    }
    let message = pi1_xd_to_wots96_msg(&proof.a, dynamic_input);
    Ok(TxAssertWitness { wots_sig: Wots96::sign(assert_secret_key, &message).to_vec() })
}

impl TxAssertWitness {
    pub fn recover_pi1_xd_without_verify(&self) -> Option<(ark_bn254::G1Affine, Fr)> {
        let message = Wots96::signature_to_message(&to_real_wots_sig(&self.wots_sig).ok()?);
        let x = Fq::deserialize_uncompressed(&message[..32]).ok()?;
        let y = Fq::deserialize_uncompressed(&message[32..64]).ok()?;
        let dynamic_input = Fr::deserialize_uncompressed(&message[64..]).ok()?;
        Some((ark_bn254::G1Affine::new(x, y), dynamic_input))
    }
}

pub fn assert_wots_message(assert_witness: &TxAssertWitness) -> Result<[u8; 96]> {
    Ok(Wots96::signature_to_message(&to_real_wots_sig(&assert_witness.wots_sig)?))
}

#[allow(clippy::too_many_arguments)]
pub fn build_real_challenge_assert_witness(
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    static_input: Fr,
    operator_wots_pubkey: &OperatorAssertPublicKey,
    assert_witness: &TxAssertWitness,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    if finalized_indices.len() != BABE_M_CC {
        bail!("verifier state must contain exactly {BABE_M_CC} finalized BABE instances");
    }
    let verifier = restore_real_verifier(private_state, package, vk, static_input)?;
    if from_real_package(&verifier.commit()) != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }
    let real_assert = RealTxAssertWitness { wots_sig: to_real_wots_sig(&assert_witness.wots_sig)? };
    let witness = build_challenge_assert_witness(
        &verifier,
        &real_assert,
        operator_wots_pubkey,
        finalized_indices[0],
    )
    .ok_or_else(|| anyhow::anyhow!("invalid operator assertion WOTS signature"))?;

    Ok(BabeChallengeAssertWitness {
        verifier_index,
        witness: SerializableChallengeAssertWitness {
            input_labels: witness.input_labels,
            wots_sig: witness.wots_sig.to_vec(),
        },
    })
}

pub fn recover_real_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    proof: &ark_groth16::Proof<Bn254>,
    vk: Groth16VerifyingKey<Bn254>,
    dynamic_input: Fr,
) -> Result<BabeWronglyChallengedWitness> {
    let real_state = ProverSetupState {
        wots_sk_p: Wots96::generate_secret_key(),
        finalized: prover_state
            .finalized
            .iter()
            .map(to_real_finalized)
            .collect::<Result<Vec<_>>>()?,
        soldering: to_real_soldering(&prover_state.soldering)?,
        h_msgs: prover_state.h_msgs.clone(),
        presigs_v: babe_verifier_presign(),
    };
    let real_challenge = RealTxChallengeAssertWitness {
        input_labels: challenge_witness.witness.input_labels.clone(),
        wots_sig: to_real_wots_sig(&challenge_witness.witness.wots_sig)?,
        sig_v: BabeBtcSig::VerifierLiveSig,
        sig_p: BabeBtcSig::ProverPresigChallengeAssert,
    };
    let (witness, finalized_id) =
        babe_prover_wrongly_challenged_cac(&vk, dynamic_input, &real_challenge, proof, &real_state)
            .ok_or_else(|| anyhow::anyhow!("failed to recover wrongly challenged BABE message"))?;

    Ok(BabeWronglyChallengedWitness {
        verifier_index: finalized_id,
        final_msg: witness.msg.to_vec(),
    })
}

fn ensure_real_gc_assets_configured() -> Result<()> {
    for name in [
        "FGC_GATES_PATH",
        "FGC_OUT_INDICES_PATH",
        "SGC_GATES_PATH",
        "SGC_OUT_INDICES_PATH",
        "FGC_COMPACT_GATES_PATH",
        "FGC_COMPACT_OUT_INDICES_PATH",
        "SGC_COMPACT_GATES_PATH",
        "SGC_COMPACT_OUT_INDICES_PATH",
    ] {
        let path = PathBuf::from(
            std::env::var(name)
                .map_err(|_| anyhow::anyhow!("{name} is required for real BABE setup"))?,
        );
        if !path.is_file() {
            bail!("{name} does not point to a readable file: {}", path.display());
        }
    }
    Ok(())
}

fn statement_digest(vk: &Groth16VerifyingKey<Bn254>, static_input: Fr) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)?;
    static_input.serialize_compressed(&mut bytes)?;
    Ok(hash32(&bytes))
}

fn restore_real_verifier(
    state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    vk: &Groth16VerifyingKey<Bn254>,
    static_input: Fr,
) -> Result<BABEVerifier> {
    Ok(BABEVerifier::from_state(
        state.instance_seeds.clone(),
        to_real_package(package),
        state.light_secrets.clone(),
        vk,
        static_input,
    ))
}

fn validate_finalized_indices(
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> Result<()> {
    let finalized_set = finalized_indices.iter().copied().collect::<HashSet<_>>();
    if finalized_set.len() != finalized_indices.len() {
        bail!("duplicate finalized index");
    }
    if finalized_indices.is_empty() {
        bail!("at least one finalized index is required");
    }
    if finalized_indices.iter().any(|index| *index >= package.commits.len()) {
        bail!("finalized index out of range");
    }
    Ok(())
}

fn from_real_package(package: &RealCACSetupPackage) -> CACSetupPackage {
    CACSetupPackage { commits: package.commits.iter().map(from_real_commit).collect() }
}

fn from_real_commit(commit: &RealCACInstanceCommit) -> CACInstanceCommit {
    CACInstanceCommit {
        epk: commit.epk.clone(),
        constant_commits_0: commit.constant_commits_0,
        constant_commits_1: commit.constant_commits_1.clone(),
        b_blind_commit: commit.b_blind_commit,
        h_msg: commit.h_msg,
        h_ct_setup: commit.h_ct_setup,
        com_adaptor: commit.com_adaptor,
        com_gc: commit.com_gc,
    }
}

fn to_real_package(package: &CACSetupPackage) -> RealCACSetupPackage {
    RealCACSetupPackage {
        commits: package
            .commits
            .iter()
            .map(|commit| RealCACInstanceCommit {
                epk: commit.epk.clone(),
                constant_commits_0: commit.constant_commits_0,
                constant_commits_1: commit.constant_commits_1.clone(),
                b_blind_commit: commit.b_blind_commit,
                h_msg: commit.h_msg,
                h_ct_setup: commit.h_ct_setup,
                com_adaptor: commit.com_adaptor,
                com_gc: commit.com_gc,
            })
            .collect(),
    }
}

fn from_real_finalized(
    finalized: &RealFinalizedInstanceData,
    package: &CACSetupPackage,
) -> Result<FinalizedInstanceData> {
    let mut b = Vec::new();
    finalized.b.serialize_compressed(&mut b)?;
    let real_data = RealFinalizedPayload {
        ciphertext_sets: finalized
            .ciphertext_sets
            .each_ref()
            .map(|set| set.iter().map(|value| value.map(|label| label.0)).collect()),
        adaptor_tables: finalized.adaptor_tables.each_ref().map(from_real_adaptor_table),
        ct_setup: SerializableSetupCt {
            ct2_r_delta_g2: finalized.ct_setup.ct2_r_delta_g2.clone(),
            ct3_masked_msg: finalized.ct_setup.ct3_masked_msg.clone(),
        },
        constant_labels_0: finalized.constant_labels_0.map(|label| label.0),
        constant_labels_1: finalized.constant_labels_1.iter().map(|label| label.0).collect(),
        b,
    };
    expand_compact_finalized_instance(
        package,
        CompactFinalizedInstanceData { index: finalized.index, real_data },
    )
}

fn expand_compact_finalized_instance(
    package: &CACSetupPackage,
    finalized: CompactFinalizedInstanceData,
) -> Result<FinalizedInstanceData> {
    let commit = package
        .commits
        .get(finalized.index)
        .ok_or_else(|| anyhow::anyhow!("finalized index {} out of range", finalized.index))?;
    if commit.epk.len() != 3 * N {
        bail!(
            "finalized index {} has {} BABE input commitments; expected {}",
            finalized.index,
            commit.epk.len(),
            3 * N,
        );
    }
    let dummy = padding_wire_hashes()[0];
    let wire_hashes = interleave_dummy_positions(
        &commit.epk[..N],
        &commit.epk[N..2 * N],
        &commit.epk[2 * N..],
        dummy,
    )
    .iter()
    .map(to_wire_hash)
    .collect();
    Ok(FinalizedInstanceData {
        index: finalized.index,
        final_msg_hash: commit.h_msg,
        wire_hashes,
        real_data: Some(finalized.real_data),
    })
}

fn to_real_finalized(finalized: &FinalizedInstanceData) -> Result<RealFinalizedInstanceData> {
    let payload = finalized.real_data.as_ref().ok_or_else(|| {
        anyhow::anyhow!("finalized index {} lacks real BABE payload", finalized.index)
    })?;
    Ok(RealFinalizedInstanceData {
        index: finalized.index,
        ciphertext_sets: payload
            .ciphertext_sets
            .each_ref()
            .map(|set| set.iter().map(|value| value.map(S)).collect()),
        adaptor_tables: [
            to_real_adaptor_table(&payload.adaptor_tables[0])?,
            to_real_adaptor_table(&payload.adaptor_tables[1])?,
        ],
        ct_setup: RealSetupCt {
            ct2_r_delta_g2: payload.ct_setup.ct2_r_delta_g2.clone(),
            ct3_masked_msg: payload.ct_setup.ct3_masked_msg.clone(),
        },
        constant_labels_0: payload.constant_labels_0.map(S),
        constant_labels_1: payload.constant_labels_1.iter().copied().map(S).collect(),
        b: ark_bn254::G1Affine::deserialize_compressed(payload.b.as_slice())?,
    })
}

fn from_real_adaptor_table(table: &RealSparseAdaptorTable) -> SerializableSparseAdaptorTable {
    SerializableSparseAdaptorTable {
        entries: table
            .entries
            .iter()
            .map(|entry| SerializableSparseAdaptorEntry {
                x: from_real_adaptor_row(&entry.x),
                y: from_real_adaptor_row(&entry.y),
                z: from_real_adaptor_row(&entry.z),
            })
            .collect(),
    }
}

fn from_real_adaptor_row(row: &RealSparseAdaptorRow) -> SerializableSparseAdaptorRow {
    let mut offset = Vec::new();
    row.offset.serialize_compressed(&mut offset).expect("serialize adaptor offset");
    SerializableSparseAdaptorRow { cts: row.cts.clone(), offset }
}

fn to_real_adaptor_table(table: &SerializableSparseAdaptorTable) -> Result<RealSparseAdaptorTable> {
    Ok(RealSparseAdaptorTable {
        entries: table
            .entries
            .iter()
            .map(|entry| {
                Ok(RealSparseAdaptorEntry {
                    x: to_real_adaptor_row(&entry.x)?,
                    y: to_real_adaptor_row(&entry.y)?,
                    z: to_real_adaptor_row(&entry.z)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn to_real_adaptor_row(row: &SerializableSparseAdaptorRow) -> Result<RealSparseAdaptorRow> {
    Ok(RealSparseAdaptorRow {
        cts: row.cts.clone(),
        offset: Fq::deserialize_compressed(row.offset.as_slice())?,
    })
}

fn from_real_soldering(soldering: &RealSolderingData) -> Result<SolderingData> {
    let output = soldering.soldering_proof.output().map_err(anyhow::Error::msg)?;
    Ok(SolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldered_output: SolderedLabelsData {
            base_commitment: output.base_commitment.clone(),
            deltas: output.deltas.clone(),
            commitments: output.commitments.clone(),
        },
        proof: bincode::serialize(&soldering.soldering_proof.proof)?,
    })
}

fn expand_compact_soldering_data(soldering: CompactSolderingData) -> Result<SolderingData> {
    if soldering.proof.is_empty() {
        bail!("soldering proof is empty");
    }
    let proof = RealSolderingProof { proof: bincode::deserialize(&soldering.proof)? };
    let output = proof.output().map_err(anyhow::Error::msg)?;
    Ok(SolderingData {
        finalized_indices: soldering.finalized_indices,
        soldered_output: SolderedLabelsData {
            base_commitment: output.base_commitment.clone(),
            deltas: output.deltas.clone(),
            commitments: output.commitments.clone(),
        },
        proof: soldering.proof,
    })
}

fn to_real_soldering(soldering: &SolderingData) -> Result<RealSolderingData> {
    if soldering.proof.is_empty() {
        bail!("soldering proof is empty");
    }
    Ok(RealSolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldering_proof: RealSolderingProof { proof: bincode::deserialize(&soldering.proof)? },
    })
}

fn to_real_wots_sig(wots_sig: &[[u8; 21]]) -> Result<<Wots96 as Wots>::Signature> {
    wots_sig.try_into().map_err(|_| {
        anyhow::anyhow!(
            "WOTS signature has {} digit signatures; expected {WOTS_SIG_COUNT}",
            wots_sig.len()
        )
    })
}

fn padding_wire_hashes() -> [[[u8; 20]; 2]; 4] {
    let false_hash = label_hash(&vec![0u8; 16]);
    let true_hash = label_hash(&vec![1u8; 16]);
    [[false_hash, true_hash]; 4]
}

fn deterministic_seed(index: usize) -> u64 {
    u64::from_le_bytes(hash32(&(index as u64).to_le_bytes())[0..8].try_into().expect("8 bytes"))
}

fn to_wire_hash(pair: &[[u8; 20]; 2]) -> WireHash {
    WireHash { false_label_hash: pair[0], true_label_hash: pair[1] }
}

fn hash20(data: &[u8]) -> [u8; 20] {
    let hash = hash32(data);
    hash[0..20].try_into().expect("20 bytes")
}

fn hash32(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
