use anyhow::{Context, anyhow, bail};
use bitcoin::Network;
use bitcoin::Txid;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use bitcoin_light_client_circuit::{parse_operator_public_inputs, parse_watchtower_public_inputs};
use cbft_rpc::fetch_validators;
use client::btc_chain::BTCClient;
use commit_chain::{Hash as SequencerSetHash, SequencerInfo, sequencer_hash};
use proof_builder::{PartStarkVkAttestationRequest, PartStarkVkAttestationSignature, ProofType};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Duration;
use store::localdb::LocalDB;
use store::{
    AttestationBatchStatus, PartStarkVkAttestationBatch,
    PartStarkVkAttestationSignature as StoredSignature,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use util::get_btc_block_confirms;
use zkm_verifier::Groth16Verifier;
use zkm_version::{
    PART_STARK_VK_ATTESTATION_DOMAIN_TAG, build_part_stark_vk_attestation_message,
    hash_attestation_bytes, hash_part_stark_vk, parse_zkm_version, read_zkm_version_from_file,
};

pub const ENV_ENABLE_PART_STARK_VK_ATTESTATION_GATE: &str = "ENABLE_PART_STARK_VK_ATTESTATION_GATE";
pub const ENV_ENABLE_PART_STARK_VK_ATTESTATION_WATCHER: &str =
    "ENABLE_PART_STARK_VK_ATTESTATION_WATCHER";

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_secs() as i64
}

fn parse_bool_env(var_name: &str) -> bool {
    matches!(
        std::env::var(var_name)
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

pub fn is_gate_enabled() -> bool {
    parse_bool_env(ENV_ENABLE_PART_STARK_VK_ATTESTATION_GATE)
}

pub fn is_watcher_enabled() -> bool {
    parse_bool_env(ENV_ENABLE_PART_STARK_VK_ATTESTATION_WATCHER)
}

fn normalize_hex(input: &str) -> String {
    input.trim().trim_start_matches("0x").to_ascii_lowercase()
}

fn normalize_pubkey_hex(pubkey: &PublicKey) -> String {
    hex::encode(pubkey.serialize())
}

pub(crate) fn required_signers(total: usize) -> usize {
    (total * 2).div_ceil(3)
}

fn part_stark_vk_by_version(zkm_version: &str) -> anyhow::Result<Vec<u8>> {
    let normalized =
        parse_zkm_version(zkm_version).map_err(|e| anyhow!("invalid zkm_version: {e}"))?;
    let bytes = std::panic::catch_unwind(|| Groth16Verifier::get_part_stark_vk(&normalized))
        .map_err(|_| anyhow!("failed to load part_stark_vk for zkm_version '{normalized}'"))?;
    Ok(bytes.to_vec())
}

fn attestation_digest(zkm_version: &str, part_stark_vk: &[u8]) -> anyhow::Result<[u8; 32]> {
    let msg = build_part_stark_vk_attestation_message(
        PART_STARK_VK_ATTESTATION_DOMAIN_TAG,
        zkm_version,
        part_stark_vk,
    )
    .map_err(|e| anyhow!("failed to build attestation message: {e}"))?;
    Ok(Sha256::digest(msg).into())
}

fn canonical_attestation_bytes(
    zkm_version: &str,
    part_stark_vk_hash: &str,
    sequencer_set_hash: &str,
    sequencer_set_cosmos_block_height: i64,
    sequencer_set_goat_block_height: i64,
    threshold: usize,
    signatures: &[PartStarkVkAttestationSignature],
) -> Vec<u8> {
    let mut signatures = signatures.to_vec();
    signatures.sort_by(|a, b| a.signer_pubkey.cmp(&b.signer_pubkey));

    let mut payload = Vec::new();
    payload.extend_from_slice(PART_STARK_VK_ATTESTATION_DOMAIN_TAG.as_bytes());
    payload.push(0);
    payload.extend_from_slice(zkm_version.as_bytes());
    payload.push(0);
    payload.extend_from_slice(part_stark_vk_hash.as_bytes());
    payload.push(0);
    payload.extend_from_slice(sequencer_set_hash.as_bytes());
    payload.push(0);
    payload.extend_from_slice(sequencer_set_cosmos_block_height.to_string().as_bytes());
    payload.push(0);
    payload.extend_from_slice(sequencer_set_goat_block_height.to_string().as_bytes());
    payload.push(0);
    payload.extend_from_slice(threshold.to_string().as_bytes());
    for signature in signatures {
        payload.push(0xff);
        payload.extend_from_slice(signature.signer_pubkey.as_bytes());
        payload.push(0xfe);
        payload.extend_from_slice(signature.signature.as_bytes());
    }
    payload
}

fn parse_signature(signature_hex: &str) -> anyhow::Result<Signature> {
    let raw = hex::decode(normalize_hex(signature_hex))
        .with_context(|| format!("failed to decode signature hex: '{signature_hex}'"))?;
    if raw.len() == 64 {
        Signature::from_compact(&raw).map_err(|e| anyhow!("invalid compact ecdsa signature: {e}"))
    } else {
        Signature::from_der(&raw).map_err(|e| anyhow!("invalid der ecdsa signature: {e}"))
    }
}

fn verify_attestation_signatures(
    digest: [u8; 32],
    sequencer_pubkeys: &HashMap<String, PublicKey>,
    signatures: &[PartStarkVkAttestationSignature],
) -> anyhow::Result<Vec<PartStarkVkAttestationSignature>> {
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(digest);
    let mut seen_signers = HashSet::new();
    let mut valid = Vec::new();

    for item in signatures {
        let signer = PublicKey::from_slice(
            &hex::decode(normalize_hex(&item.signer_pubkey))
                .with_context(|| format!("invalid signer pubkey hex '{}'", item.signer_pubkey))?,
        )
        .with_context(|| format!("invalid signer pubkey '{}'", item.signer_pubkey))?;
        let signer_hex = normalize_pubkey_hex(&signer);
        if !sequencer_pubkeys.contains_key(&signer_hex) {
            continue;
        }

        let sig = parse_signature(&item.signature)?;
        if secp.verify_ecdsa(&msg, &sig, &signer).is_err() {
            continue;
        }

        if seen_signers.insert(signer_hex.clone()) {
            valid.push(PartStarkVkAttestationSignature {
                signer_pubkey: signer_hex,
                signature: normalize_hex(&item.signature),
            });
        }
    }
    Ok(valid)
}

fn sequencer_pubkeys_by_sequencers(
    sequencers: &[SequencerInfo],
) -> anyhow::Result<HashMap<String, PublicKey>> {
    let mut map = HashMap::with_capacity(sequencers.len());
    for sequencer in sequencers {
        let pubkey = PublicKey::from_slice(&sequencer.pub_key).with_context(|| {
            format!("invalid sequencer secp256k1 pubkey: {}", sequencer.address)
        })?;
        map.insert(normalize_pubkey_hex(&pubkey), pubkey);
    }
    Ok(map)
}

fn verify_sequencer_set_hash(
    sequencers: &[SequencerInfo],
    expected_hash: &str,
) -> anyhow::Result<()> {
    let got_hash = match sequencer_hash(sequencers) {
        SequencerSetHash::Sha256(hash) => hex::encode(hash),
        _ => bail!("unsupported sequencer hash type"),
    };
    if normalize_hex(&got_hash) != normalize_hex(expected_hash) {
        bail!(
            "sequencer set hash mismatch, expected {}, got {}",
            normalize_hex(expected_hash),
            normalize_hex(&got_hash)
        );
    }
    Ok(())
}

fn tx_contains_attestation_hash(
    tx: &bitcoin::Transaction,
    attestation_hash: &str,
) -> anyhow::Result<bool> {
    let attestation_hash =
        hex::decode(normalize_hex(attestation_hash)).context("invalid attestation hash hex")?;
    Ok(tx.output.iter().any(|output| {
        output
            .script_pubkey
            .as_bytes()
            .windows(attestation_hash.len())
            .any(|w| w == attestation_hash.as_slice())
    }))
}

pub(crate) async fn verify_and_store_part_stark_vk_attestation(
    local_db: &LocalDB,
    cosmos_rpc_url: &str,
    request: &PartStarkVkAttestationRequest,
) -> anyhow::Result<(i64, String, String, usize, usize, AttestationBatchStatus)> {
    let zkm_version =
        parse_zkm_version(&request.zkm_version).map_err(|e| anyhow!("invalid zkm_version: {e}"))?;
    if request.signatures.is_empty() {
        bail!("attestation signatures are empty");
    }
    if request.sequencer_set_cosmos_block_height <= 0 {
        bail!("invalid sequencer_set_cosmos_block_height");
    }

    let mut storage = local_db.acquire().await?;
    let hash_change = storage
        .find_sequencer_set_hash_change_by_cosmos_block_height(
            request.sequencer_set_cosmos_block_height,
        )
        .await?
        .ok_or_else(|| {
            anyhow!(
                "sequencer set hash record not found at cosmos block {}",
                request.sequencer_set_cosmos_block_height
            )
        })?;
    drop(storage);

    let validators = fetch_validators(
        cosmos_rpc_url,
        u64::try_from(request.sequencer_set_cosmos_block_height)
            .context("cosmos block height must be non-negative")?,
    )
    .await?;
    if validators.is_empty() {
        bail!(
            "validators set is empty at cosmos block {}",
            request.sequencer_set_cosmos_block_height
        );
    }
    let sequencers: Vec<SequencerInfo> = validators.iter().cloned().map(Into::into).collect();
    verify_sequencer_set_hash(&sequencers, &hash_change.validators_hash)?;
    let sequencer_pubkeys = sequencer_pubkeys_by_sequencers(&sequencers)?;

    let part_stark_vk = part_stark_vk_by_version(&zkm_version)?;
    let part_stark_vk_hash = hash_part_stark_vk(&part_stark_vk);
    let digest = attestation_digest(&zkm_version, &part_stark_vk)?;
    let valid_signatures =
        verify_attestation_signatures(digest, &sequencer_pubkeys, &request.signatures)?;
    let required = required_signers(sequencer_pubkeys.len());
    let verified_signers = valid_signatures.len();
    if verified_signers < required {
        bail!(
            "attestation threshold not met, valid signatures: {}, required: {}",
            verified_signers,
            required
        );
    }

    let attestation_hash = hash_attestation_bytes(&canonical_attestation_bytes(
        &zkm_version,
        &part_stark_vk_hash,
        &normalize_hex(&hash_change.validators_hash),
        hash_change.cosmos_block_height,
        hash_change.goat_block_height,
        required,
        &valid_signatures,
    ));

    let now = now_secs();
    let status = AttestationBatchStatus::LocallyVerified;
    let mut tx = local_db.start_transaction().await?;
    let batch_id = tx
        .create_part_stark_vk_attestation_batch(&PartStarkVkAttestationBatch {
            id: 0,
            domain_tag: PART_STARK_VK_ATTESTATION_DOMAIN_TAG.to_string(),
            zkm_version: zkm_version.clone(),
            part_stark_vk_hash: part_stark_vk_hash.clone(),
            sequencer_set_hash: normalize_hex(&hash_change.validators_hash),
            sequencer_set_cosmos_block_height: hash_change.cosmos_block_height,
            sequencer_set_goat_block_height: hash_change.goat_block_height,
            sequencer_set_size: i64::try_from(sequencer_pubkeys.len())
                .context("sequencer set size overflow")?,
            threshold: i64::try_from(required).context("threshold overflow")?,
            attestation_hash: attestation_hash.clone(),
            status: status.to_string(),
            bitcoin_txid: None,
            bitcoin_confirmed_height: None,
            locally_verified_at: now,
            bitcoin_confirmed_at: None,
            created_at: now,
        })
        .await?;

    for signature in valid_signatures {
        tx.create_part_stark_vk_attestation_signature(&StoredSignature {
            id: 0,
            batch_id,
            signer_pubkey: signature.signer_pubkey,
            signature: signature.signature,
            created_at: now,
        })
        .await?;
    }
    tx.commit().await?;
    Ok((batch_id, part_stark_vk_hash, attestation_hash, verified_signers, required, status))
}

pub(crate) async fn bind_part_stark_vk_attestation_anchor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    batch_id: i64,
    bitcoin_txid: &str,
) -> anyhow::Result<PartStarkVkAttestationBatch> {
    let txid = Txid::from_str(bitcoin_txid)
        .with_context(|| format!("invalid bitcoin txid '{bitcoin_txid}'"))?;
    let mut storage = local_db.acquire().await?;
    let batch = storage
        .find_part_stark_vk_attestation_batch_by_id(batch_id)
        .await?
        .ok_or_else(|| anyhow!("attestation batch not found: {batch_id}"))?;
    drop(storage);

    let tx = btc_client
        .get_tx(&txid)
        .await?
        .ok_or_else(|| anyhow!("bitcoin anchor tx not found: {txid}"))?;
    if !tx_contains_attestation_hash(&tx, &batch.attestation_hash)? {
        bail!(
            "bitcoin anchor tx {} does not include attestation hash {}",
            txid,
            batch.attestation_hash
        );
    }
    let tx_info = btc_client
        .get_tx_info(&txid)
        .await?
        .ok_or_else(|| anyhow!("bitcoin anchor tx info not found: {txid}"))?;
    let confirmed_height = tx_info.status.block_height.map(i64::from);
    let confirmations_required = i64::from(get_btc_block_confirms(btc_client.network()));
    let tip_height = i64::from(btc_client.get_height().await?);
    let status = if tx_info.status.confirmed {
        if let Some(height) = confirmed_height {
            if tip_height.saturating_sub(height).saturating_add(1) >= confirmations_required {
                AttestationBatchStatus::BitcoinConfirmed
            } else {
                AttestationBatchStatus::BitcoinPending
            }
        } else {
            AttestationBatchStatus::BitcoinPending
        }
    } else {
        AttestationBatchStatus::BitcoinPending
    };

    let bitcoin_confirmed_at =
        if status == AttestationBatchStatus::BitcoinConfirmed { Some(now_secs()) } else { None };
    let mut storage = local_db.acquire().await?;
    storage
        .update_part_stark_vk_attestation_batch_anchor(
            batch_id,
            bitcoin_txid,
            confirmed_height,
            status.clone(),
            bitcoin_confirmed_at,
        )
        .await?;
    storage
        .find_part_stark_vk_attestation_batch_by_id(batch_id)
        .await?
        .ok_or_else(|| anyhow!("attestation batch disappeared after anchor update: {batch_id}"))
}

pub(crate) async fn ensure_part_stark_vk_attested(
    local_db: &LocalDB,
    zkm_version: &str,
) -> anyhow::Result<String> {
    if !is_gate_enabled() {
        return Ok(String::new());
    }

    let normalized =
        parse_zkm_version(zkm_version).map_err(|e| anyhow!("invalid zkm_version: {e}"))?;
    let part_stark_vk_hash = hash_part_stark_vk(&part_stark_vk_by_version(&normalized)?);
    let mut storage = local_db.acquire().await?;
    storage
        .assert_confirmed_part_stark_vk_attestation_by_domain_version_and_hash(
            PART_STARK_VK_ATTESTATION_DOMAIN_TAG,
            &normalized,
            &part_stark_vk_hash,
        )
        .await?;
    Ok(part_stark_vk_hash)
}

pub(crate) async fn ensure_part_stark_vk_hash_attested(
    local_db: &LocalDB,
    part_stark_vk_hash: &str,
) -> anyhow::Result<()> {
    if !is_gate_enabled() {
        return Ok(());
    }

    let mut storage = local_db.acquire().await?;
    storage
        .assert_confirmed_part_stark_vk_attestation_by_hash(
            PART_STARK_VK_ATTESTATION_DOMAIN_TAG,
            part_stark_vk_hash,
        )
        .await?;
    Ok(())
}

pub(crate) async fn ensure_declared_recursive_part_stark_vks_attested(
    local_db: &LocalDB,
    proof_type: ProofType,
    public_inputs: &[u8],
) -> anyhow::Result<()> {
    if !is_gate_enabled() {
        return Ok(());
    }

    match proof_type {
        ProofType::Watchtower => {
            let (_, _, header_hash, commit_hash, state_hash) =
                parse_watchtower_public_inputs(public_inputs)
                    .map_err(|e| anyhow!("failed to parse watchtower public inputs: {e}"))?;
            ensure_part_stark_vk_hash_attested(local_db, &hex::encode(header_hash)).await?;
            ensure_part_stark_vk_hash_attested(local_db, &hex::encode(commit_hash)).await?;
            ensure_part_stark_vk_hash_attested(local_db, &hex::encode(state_hash)).await?;
        }
        ProofType::Operator => {
            let (_, _, _, header_hash, commit_hash, state_hash) =
                parse_operator_public_inputs(public_inputs)
                    .map_err(|e| anyhow!("failed to parse operator public inputs: {e}"))?;
            ensure_part_stark_vk_hash_attested(local_db, &hex::encode(header_hash)).await?;
            ensure_part_stark_vk_hash_attested(local_db, &hex::encode(commit_hash)).await?;
            ensure_part_stark_vk_hash_attested(local_db, &hex::encode(state_hash)).await?;
        }
        _ => {}
    }

    Ok(())
}

pub(crate) async fn ensure_input_proof_part_stark_vk_attested(
    local_db: &LocalDB,
    input_proof_path: &str,
) -> anyhow::Result<String> {
    if !is_gate_enabled() {
        return Ok(String::new());
    }
    let zkm_version = read_zkm_version_from_file(input_proof_path).map_err(|e| {
        anyhow!("failed to read zkm_version from input proof '{}': {e}", input_proof_path)
    })?;
    ensure_part_stark_vk_attested(local_db, &zkm_version).await
}

pub(crate) async fn sync_bitcoin_anchor_statuses(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    let mut storage = local_db.acquire().await?;
    let statuses = vec![
        AttestationBatchStatus::BitcoinPending.to_string(),
        AttestationBatchStatus::BitcoinConfirmed.to_string(),
    ];
    let batches = storage.find_part_stark_vk_attestation_batches_by_statuses(&statuses).await?;
    drop(storage);

    let confirmations_required = i64::from(get_btc_block_confirms(btc_client.network()));
    let tip_height = i64::from(btc_client.get_height().await?);
    let mut pending_updates = Vec::new();
    for batch in batches {
        let Some(bitcoin_txid) = batch.bitcoin_txid.as_ref() else {
            continue;
        };
        let txid = Txid::from_str(bitcoin_txid)
            .with_context(|| format!("invalid stored bitcoin txid '{bitcoin_txid}'"))?;
        let tx = match btc_client.get_tx(&txid).await? {
            Some(tx) => tx,
            None => {
                if batch.status == AttestationBatchStatus::BitcoinConfirmed.to_string() {
                    pending_updates.push((
                        batch.id,
                        bitcoin_txid.to_string(),
                        None,
                        AttestationBatchStatus::BitcoinReorged,
                        None,
                    ));
                }
                continue;
            }
        };
        if !tx_contains_attestation_hash(&tx, &batch.attestation_hash)? {
            pending_updates.push((
                batch.id,
                bitcoin_txid.to_string(),
                None,
                AttestationBatchStatus::BitcoinReorged,
                None,
            ));
            continue;
        }

        let tx_info = match btc_client.get_tx_info(&txid).await? {
            Some(info) => info,
            None => continue,
        };
        let confirmed_height = tx_info.status.block_height.map(i64::from);
        let new_status = if tx_info.status.confirmed {
            if let Some(height) = confirmed_height {
                if tip_height.saturating_sub(height).saturating_add(1) >= confirmations_required {
                    AttestationBatchStatus::BitcoinConfirmed
                } else {
                    AttestationBatchStatus::BitcoinPending
                }
            } else {
                AttestationBatchStatus::BitcoinPending
            }
        } else if batch.status == AttestationBatchStatus::BitcoinConfirmed.to_string() {
            AttestationBatchStatus::BitcoinReorged
        } else {
            AttestationBatchStatus::BitcoinPending
        };

        let new_confirmed_at = if new_status == AttestationBatchStatus::BitcoinConfirmed {
            Some(now_secs())
        } else {
            None
        };
        if batch.status != new_status.to_string()
            || batch.bitcoin_confirmed_height != confirmed_height
        {
            pending_updates.push((
                batch.id,
                bitcoin_txid.to_string(),
                confirmed_height,
                new_status,
                new_confirmed_at,
            ));
        }
    }
    if pending_updates.is_empty() {
        return Ok(());
    }

    let mut storage = local_db.acquire().await?;
    for (batch_id, bitcoin_txid, confirmed_height, status, confirmed_at) in pending_updates {
        storage
            .update_part_stark_vk_attestation_batch_anchor(
                batch_id,
                &bitcoin_txid,
                confirmed_height,
                status,
                confirmed_at,
            )
            .await?;
    }
    Ok(())
}

pub(crate) fn spawn_bitcoin_anchor_watcher_task(
    local_db: LocalDB,
    esplora_url: String,
    network: Network,
    interval_secs: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<Result<String, String>> {
    tokio::spawn(async move {
        let btc_client = BTCClient::new(network, Some(&esplora_url));
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                    if let Err(err) = sync_bitcoin_anchor_statuses(&local_db, &btc_client).await {
                        warn!("part_stark_vk attestation watcher sync failed: {err:?}");
                    }
                }
                _ = cancellation_token.cancelled() => {
                    info!("part_stark_vk attestation watcher received shutdown signal");
                    return Ok("part_stark_vk_attestation_watcher_shutdown".to_string());
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn sign_digest_hex(secret: &SecretKey, digest: [u8; 32]) -> String {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(digest);
        let sig = secp.sign_ecdsa(&msg, secret);
        hex::encode(sig.serialize_compact())
    }

    #[test]
    fn test_required_signers_two_thirds_round_up() {
        assert_eq!(required_signers(1), 1);
        assert_eq!(required_signers(2), 2);
        assert_eq!(required_signers(3), 2);
        assert_eq!(required_signers(4), 3);
        assert_eq!(required_signers(5), 4);
    }

    #[test]
    fn test_verify_attestation_signatures_filters_invalid_and_duplicates() {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let sk3 = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &sk1);
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);
        let pk3 = PublicKey::from_secret_key(&secp, &sk3);

        let mut set = HashMap::new();
        set.insert(normalize_pubkey_hex(&pk1), pk1);
        set.insert(normalize_pubkey_hex(&pk2), pk2);

        let digest = [7u8; 32];
        let sig1 = sign_digest_hex(&sk1, digest);
        let sig2 = sign_digest_hex(&sk2, digest);
        let sig3 = sign_digest_hex(&sk3, digest);

        let input = vec![
            PartStarkVkAttestationSignature {
                signer_pubkey: normalize_pubkey_hex(&pk1),
                signature: sig1.clone(),
            },
            PartStarkVkAttestationSignature {
                signer_pubkey: normalize_pubkey_hex(&pk1),
                signature: sig1,
            },
            PartStarkVkAttestationSignature {
                signer_pubkey: normalize_pubkey_hex(&pk2),
                signature: sig2,
            },
            PartStarkVkAttestationSignature {
                signer_pubkey: normalize_pubkey_hex(&pk3),
                signature: sig3,
            },
        ];

        let valid = verify_attestation_signatures(digest, &set, &input).unwrap();
        assert_eq!(valid.len(), 2);
    }
}
