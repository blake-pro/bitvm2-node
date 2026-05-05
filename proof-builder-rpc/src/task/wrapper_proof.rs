use crate::task::current_time_secs;
use operator_wrapper_proof::OperatorWrapperProofBuilder;
use proof_builder::{ProofBuilder, ProofRequest};
use std::path::Path;
use std::time::Duration;
use store::localdb::LocalDB;
use store::{ProofState, WrapperProof};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[tracing::instrument(level = "info", skip(local_db))]
pub(crate) async fn create_missing_wrapper_tasks(
    local_db: &LocalDB,
    genesis_sequencer_commit_txid: &str,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    let operator_proofs = storage_processor.find_proven_operator_proofs_without_wrapper(32).await?;
    let mut created = 0u64;

    for operator_proof in operator_proofs {
        let Some(operator_path_to_proof) = operator_proof.path_to_proof.clone() else {
            continue;
        };
        let operator_vk_hash =
            read_utf8_sidecar(&format!("{operator_path_to_proof}.vk_hash.bin")).unwrap_or_default();
        let now = current_time_secs();
        let wrapper_proof = WrapperProof {
            operator_proof_id: operator_proof.id,
            instance_id: operator_proof.instance_id,
            graph_id: operator_proof.graph_id,
            execution_layer_block_number: operator_proof.execution_layer_block_number,
            operator_path_to_proof,
            operator_vk_hash,
            genesis_sequencer_commit_txid: genesis_sequencer_commit_txid.to_string(),
            operator_public_value_hex: operator_proof.public_value_hex.clone(),
            proof_state: ProofState::New.to_i64(),
            created_at: now,
            updated_at: now,
            ..Default::default()
        };

        match storage_processor.create_wrapper_proof(&wrapper_proof).await {
            Ok(rows) => created += rows,
            Err(err) if err.to_string().contains("UNIQUE") => {
                tracing::debug!(
                    operator_proof_id = operator_proof.id,
                    "wrapper task already exists"
                );
            }
            Err(err) => return Err(err),
        }
    }

    Ok(created)
}

#[tracing::instrument(level = "info", skip(local_db, cancellation_token))]
pub(crate) fn spawn_wrapper_proof_task(
    args: operator_wrapper_proof::Args,
    local_db: LocalDB,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<operator_wrapper_proof::Args>> {
    let args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Wrapper proof generate task cancelled");
            }
        }

        let builder = OperatorWrapperProofBuilder::new();
        let scan_interval = if args.scan_interval == 0 { interval } else { args.scan_interval };
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(scan_interval)) => {
                    if args.genesis_sequencer_commit_txid.is_empty() {
                        tracing::warn!("Wrapper proof task skipped: genesis_sequencer_commit_txid is empty");
                        continue;
                    }

                    let created = create_missing_wrapper_tasks(
                        &local_db,
                        &args.genesis_sequencer_commit_txid,
                    ).await?;
                    if created > 0 {
                        tracing::info!("created {created} wrapper proof tasks");
                    }

                    let wrapper_task = {
                        let mut storage_processor = local_db.acquire().await?;
                        storage_processor
                            .claim_next_wrapper_proof()
                            .await?
                    };
                    let Some(wrapper_task) = wrapper_task else {
                        tracing::debug!("No wrapper proof task found");
                        continue;
                    };

                    let output = wrapper_output_path(&args.output, &wrapper_task);
                    let ctx = ProofRequest::WrapperProofRequest {
                        operator_proof_id: wrapper_task.operator_proof_id,
                        operator_input_proof: wrapper_task.operator_path_to_proof.clone(),
                        graph_id: *wrapper_task.graph_id.as_bytes(),
                        genesis_sequencer_commit_txid: wrapper_task.genesis_sequencer_commit_txid.clone(),
                        output: output.clone(),
                    };

                    let proving_start = tokio::time::Instant::now();
                    let result = builder.build_proof(&ctx).and_then(|(input, proof, cycles, proving_time)| {
                        let zkm_version = proof.zkm_version.clone();
                        let (public_value_hex, proof_size) =
                            builder.save_proof(&ctx, &input, cycles, proof)?;
                        Ok((cycles, proving_time, public_value_hex, proof_size, zkm_version))
                    });

                    match result {
                        Ok((cycles, proving_time, public_value_hex, proof_size, zkm_version)) => {
                            let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                            let mut storage_processor = local_db.acquire().await?;
                            let affected = storage_processor
                                .update_wrapper_proof_success(
                                    wrapper_task.id,
                                    output,
                                    public_value_hex,
                                    proof_size as i64,
                                    cycles as i64,
                                    proving_time as i64,
                                    &zkm_version,
                                )
                                .await?;
                            tracing::info!(
                                wrapper_proof_id = wrapper_task.id,
                                operator_proof_id = wrapper_task.operator_proof_id,
                                proving_duration_ms = proving_duration as i64,
                                affected,
                                "wrapper proof generated"
                            );
                        }
                        Err(err) => {
                            let mut storage_processor = local_db.acquire().await?;
                            storage_processor
                                .update_wrapper_proof_failure(wrapper_task.id)
                                .await?;
                            tracing::warn!(
                                wrapper_proof_id = wrapper_task.id,
                                operator_proof_id = wrapper_task.operator_proof_id,
                                error = %err,
                                "wrapper proof generation failed"
                            );
                        }
                    }
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Wrapper proof generate task cancelled");
                }
            }
        }
    })
}

fn wrapper_output_path(output: &str, wrapper_task: &WrapperProof) -> String {
    let path = Path::new(output);
    let output_dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    output_dir
        .join(format!(
            "{}-{}.bin",
            wrapper_task.graph_id.as_simple(),
            wrapper_task.operator_proof_id
        ))
        .to_string_lossy()
        .to_string()
}

fn read_utf8_sidecar(path: &str) -> anyhow::Result<String> {
    Ok(String::from_utf8(std::fs::read(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::{OperatorProof, create_local_db};
    use uuid::Uuid;

    #[tokio::test]
    async fn create_missing_wrapper_tasks_is_unique_and_only_consumes_proven_operators() {
        let local_db = create_local_db("sqlite::memory:").await;
        let instance_id = Uuid::parse_str("00112233445566778899aabbccddeeff").unwrap();
        let graph_id = Uuid::parse_str("ffeeddccbbaa99887766554433221100").unwrap();
        let new_graph_id = Uuid::parse_str("11111111111111111111111111111111").unwrap();
        let now = current_time_secs();

        {
            let mut storage_processor = local_db.acquire().await.unwrap();
            storage_processor
                .create_operator_proof(&OperatorProof {
                    instance_id,
                    graph_id,
                    execution_layer_block_number: 9511055,
                    path_to_proof: Some("operator-proof.bin".to_string()),
                    public_value_hex: Some("operator-public".to_string()),
                    proof_state: ProofState::Proven.to_i64(),
                    created_at: now,
                    updated_at: now,
                    operator_committed_blockhash:
                        "7f7b4344adb1b8937ddb7124e4f8bba80ee9adf5e8119de76ca8736816bda246"
                            .to_string(),
                    ..Default::default()
                })
                .await
                .unwrap();
            storage_processor
                .create_operator_proof(&OperatorProof {
                    instance_id,
                    graph_id: new_graph_id,
                    execution_layer_block_number: 9511056,
                    path_to_proof: Some("operator-new.bin".to_string()),
                    proof_state: ProofState::New.to_i64(),
                    created_at: now,
                    updated_at: now,
                    operator_committed_blockhash:
                        "7f7b4344adb1b8937ddb7124e4f8bba80ee9adf5e8119de76ca8736816bda246"
                            .to_string(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        let genesis_txid = "7f7b4344adb1b8937ddb7124e4f8bba80ee9adf5e8119de76ca8736816bda246";
        assert_eq!(create_missing_wrapper_tasks(&local_db, genesis_txid).await.unwrap(), 1);
        assert_eq!(create_missing_wrapper_tasks(&local_db, genesis_txid).await.unwrap(), 0);

        let mut storage_processor = local_db.acquire().await.unwrap();
        let wrapper_proof = storage_processor
            .find_wrapper_proof_by_instance_and_graph(&instance_id, &graph_id)
            .await
            .unwrap()
            .expect("wrapper proof should exist");
        assert_eq!(wrapper_proof.operator_path_to_proof, "operator-proof.bin");
        assert_eq!(wrapper_proof.operator_public_value_hex.as_deref(), Some("operator-public"));
        assert_eq!(wrapper_proof.proof_state, ProofState::New.to_i64());
        assert!(
            storage_processor
                .find_wrapper_proof_by_instance_and_graph(&instance_id, &new_graph_id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
