use crate::api::ApiState;
use crate::api::response::{ApiErrorExt, ApiResult, ok_response};
use crate::api::validation::InputValidator;
use crate::attestation::{
    bind_part_stark_vk_attestation_anchor as bind_part_stark_vk_attestation_anchor_inner,
    ensure_declared_recursive_part_stark_vks_attested, ensure_part_stark_vk_attested,
    verify_and_store_part_stark_vk_attestation,
};
use crate::task::{
    add_operator_task, add_watchtower_task, find_operator_task, find_watchtower_task,
    update_operator_task_state, update_watchtower_task_state,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use client::btc_chain::BTCClient;
use proof_builder::{
    ChainProofDescRequest, OperatorProofDescRequest, OperatorProofRequest, OperatorProofResponse,
    OperatorProofTimeoutUpdateRequest, OperatorProofTimeoutUpdateResponse,
    PartStarkVkAttestationAnchorRequest, PartStarkVkAttestationAnchorResponse,
    PartStarkVkAttestationRequest, PartStarkVkAttestationResponse, ProofData, ProofDesc,
    ProofDescResponse, ProofType, WatchtowerProofRequest, WatchtowerProofResponse,
    WatchtowerProofTimeoutUpdateRequest, WatchtowerProofTimeoutUpdateResponse,
};
use std::sync::Arc;
use store::ProofState;
use tracing::info;

async fn ensure_proof_attested(
    api_state: &ApiState,
    proof_type: ProofType,
    proof_data: &ProofData,
) -> Result<(), String> {
    ensure_part_stark_vk_attested(&api_state.local_db, &proof_data.zkm_version)
        .await
        .map_err(|err| format!("part_stark_vk attestation check failed: {err}"))?;
    ensure_declared_recursive_part_stark_vks_attested(
        &api_state.local_db,
        proof_type,
        &proof_data.public_inputs,
    )
    .await
    .map_err(|err| format!("declared recursive part_stark_vk attestation check failed: {err}"))?;
    Ok(())
}

#[axum::debug_handler]
pub(super) async fn post_part_stark_vk_attestation(
    State(api_state): State<Arc<ApiState>>,
    Json(payload): Json<PartStarkVkAttestationRequest>,
) -> ApiResult<PartStarkVkAttestationResponse> {
    match verify_and_store_part_stark_vk_attestation(
        &api_state.local_db,
        &api_state.cosmos_rpc_url,
        &payload,
    )
    .await
    {
        Ok((
            batch_id,
            part_stark_vk_hash,
            attestation_hash,
            verified_signers,
            required_signers,
            status,
        )) => ok_response(PartStarkVkAttestationResponse {
            batch_id: Some(batch_id),
            zkm_version: payload.zkm_version,
            part_stark_vk_hash: Some(part_stark_vk_hash),
            attestation_hash: Some(attestation_hash),
            verified_signers,
            required_signers,
            status: Some(status.to_string()),
            error: None,
        }),
        Err(error) => ok_response(PartStarkVkAttestationResponse {
            batch_id: None,
            zkm_version: payload.zkm_version,
            part_stark_vk_hash: None,
            attestation_hash: None,
            verified_signers: 0,
            required_signers: 0,
            status: None,
            error: Some(error.to_string()),
        }),
    }
}

#[axum::debug_handler]
pub(super) async fn bind_part_stark_vk_attestation_anchor(
    State(api_state): State<Arc<ApiState>>,
    Path(batch_id): Path<i64>,
    Json(payload): Json<PartStarkVkAttestationAnchorRequest>,
) -> ApiResult<PartStarkVkAttestationAnchorResponse> {
    let _txid = InputValidator::validate_btc_txid(&payload.bitcoin_txid, "bitcoin_txid")?;
    let btc_client = BTCClient::new(api_state.bitcoin_network, Some(&api_state.esplora_url));
    match bind_part_stark_vk_attestation_anchor_inner(
        &api_state.local_db,
        &btc_client,
        batch_id,
        &payload.bitcoin_txid,
    )
    .await
    {
        Ok(batch) => ok_response(PartStarkVkAttestationAnchorResponse {
            batch_id,
            bitcoin_txid: batch.bitcoin_txid,
            status: Some(batch.status),
            error: None,
        }),
        Err(error) => ok_response(PartStarkVkAttestationAnchorResponse {
            batch_id,
            bitcoin_txid: None,
            status: None,
            error: Some(error.to_string()),
        }),
    }
}

#[axum::debug_handler]
pub(super) async fn get_chain_proof_task_desc(
    State(api_state): State<Arc<ApiState>>,
    Query(payload): Query<ChainProofDescRequest>,
) -> ApiResult<ProofDescResponse> {
    let mut storage_process =
        api_state.local_db.acquire().await.api_error("GET_CHAIN_PROOF_ERROR")?;

    let proof = if let Some(height) = payload.height {
        storage_process
            .find_long_running_task_proof_including_block_number(
                height,
                payload.proof_type.get_chain_name().to_string(),
            )
            .await
            .api_error("GET_CHAIN_PROOF_ERROR")?
    } else {
        storage_process
            .find_latest_long_running_task_proof_by_name(
                payload.proof_type.get_chain_name().to_string(),
            )
            .await
            .api_error("GET_CHAIN_PROOF_ERROR")?
    };

    match proof {
        Some(proof) => {
            let prev_proof_number = storage_process
                .find_long_running_task_proof_including_block_number(
                    proof.block_start - 1,
                    payload.proof_type.get_chain_name().to_string(),
                )
                .await
                .api_error("GET_CHAIN_PROOF_ERROR")?
                .map(|v| v.block_end - 1);
            let next_proof_number = storage_process
                .find_long_running_task_proof_including_block_number(
                    proof.block_end,
                    payload.proof_type.get_chain_name().to_string(),
                )
                .await
                .api_error("GET_CHAIN_PROOF_ERROR")?
                .map(|v| v.block_start);

            ok_response(ProofDescResponse {
                proof_desc: Some(ProofDesc {
                    block_start: proof.block_start,
                    block_end: proof.block_end,
                    proof_type: payload.proof_type.to_string(),
                    state: ProofState::from_i64(proof.proof_state)
                        .unwrap_or_else(|| ProofState::New)
                        .to_string(),
                    proving_cycles: proof.cycles,
                    proving_time: proof.proving_time,
                    total_time_to_proof: proof.total_time_to_proof,
                    proof_size: proof.proof_size as f64 / 1000.0, // use KiB
                    zkm_version: proof.zkm_version,
                    pub_values: proof.public_value_hex.unwrap_or("".to_string()),
                    prev_proof_number,
                    next_proof_number,
                    created_at: proof.created_at,
                    updated_at: proof.updated_at,
                }),
                error: None,
            })
        }

        None => ok_response(ProofDescResponse {
            proof_desc: None,
            error: Some("No proof found".to_string()),
        }),
    }
}

#[axum::debug_handler]
pub(super) async fn get_operator_proof_task_desc(
    State(api_state): State<Arc<ApiState>>,
    Query(payload): Query<OperatorProofDescRequest>,
) -> ApiResult<ProofDescResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    let operator_proof = find_operator_task(&api_state.local_db, instance_id, graph_id)
        .await
        .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
    match operator_proof {
        Some(operator_proof) => {
            info!("Get Operator Proof:{operator_proof:?}");
            ok_response(ProofDescResponse {
                proof_desc: Some(ProofDesc {
                    block_start: operator_proof.execution_layer_block_number,
                    block_end: operator_proof.execution_layer_block_number + 1,
                    proof_type: "Operator".to_string(),
                    state: ProofState::from_i64(operator_proof.proof_state)
                        .unwrap_or_else(|| ProofState::New)
                        .to_string(),
                    proving_cycles: operator_proof.cycles,
                    proving_time: operator_proof.proving_time,
                    total_time_to_proof: operator_proof.total_time_to_proof,
                    proof_size: operator_proof.proof_size as f64 / 1000.0, // use KiB
                    zkm_version: operator_proof.zkm_version,
                    pub_values: operator_proof.public_value_hex.unwrap_or("".to_string()),
                    prev_proof_number: None,
                    next_proof_number: None,
                    created_at: operator_proof.created_at,
                    updated_at: operator_proof.updated_at,
                }),
                error: None,
            })
        }
        None => ok_response(ProofDescResponse {
            proof_desc: None,
            error: Some("No proof found".to_string()),
        }),
    }
}

#[axum::debug_handler]
pub(super) async fn post_operator_proof_task(
    State(api_state): State<Arc<ApiState>>,
    Json(payload): Json<OperatorProofRequest>,
) -> ApiResult<OperatorProofResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    let operator_proof = find_operator_task(&api_state.local_db, instance_id, graph_id)
        .await
        .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
    match operator_proof {
        Some(operator_proof)
            if operator_proof.proof_state == ProofState::Proven.to_i64()
                && operator_proof.path_to_proof.is_some() =>
        {
            let proof_data = ProofData::load_proof_data(
                &operator_proof.path_to_proof.unwrap(),
                ProofType::Operator,
            );
            match ensure_proof_attested(&api_state, ProofType::Operator, &proof_data).await {
                Ok(_) => {
                    ok_response(OperatorProofResponse { proof_data: Some(proof_data), error: None })
                }
                Err(err) => {
                    ok_response(OperatorProofResponse { proof_data: None, error: Some(err) })
                }
            }
        }
        Some(operator_proof) => ok_response(OperatorProofResponse {
            proof_data: None,
            error: Some(format!(
                "The proof is not ready, state {}, path:{:?}",
                operator_proof.proof_state, operator_proof.path_to_proof
            )),
        }),

        None => {
            add_operator_task(
                &api_state.local_db,
                instance_id,
                graph_id,
                payload.operator_committed_blockhash,
                payload.execution_layer_block_number,
                payload.watchtower_challenge_txids.clone(),
                payload.included_watchtowers.clone(),
                payload.watchtower_challenge_init_txid.clone(),
                payload.watchtower_challenge_pubkeys.clone(),
            )
            .await
            .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
            ok_response(OperatorProofResponse {
                proof_data: None,
                error: Some("No proof found".to_string()),
            })
        }
    }
}
#[axum::debug_handler]
pub(super) async fn update_operator_proof_task_timeout(
    State(api_state): State<Arc<ApiState>>,
    Json(payload): Json<OperatorProofTimeoutUpdateRequest>,
) -> ApiResult<OperatorProofTimeoutUpdateResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    match update_operator_task_state(
        &api_state.local_db,
        instance_id,
        graph_id,
        ProofState::New,
        ProofState::Failed,
    )
    .await
    {
        Ok(rows_affected) => ok_response(OperatorProofTimeoutUpdateResponse {
            instance_id: instance_id.to_string(),
            graph_id: graph_id.to_string(),
            data: Some(format!("{rows_affected} rows affected")),
            error: None,
        }),
        Err(error) => ok_response(OperatorProofTimeoutUpdateResponse {
            instance_id: instance_id.to_string(),
            graph_id: graph_id.to_string(),
            data: None,
            error: Some(format!("update error: {error}")),
        }),
    }
}

#[axum::debug_handler]
pub(super) async fn post_watchtower_proof_task(
    State(api_state): State<Arc<ApiState>>,
    Json(payload): Json<WatchtowerProofRequest>,
) -> ApiResult<WatchtowerProofResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    let challenge_init_txid =
        InputValidator::validate_btc_txid(&payload.challenge_init_txid, "challenge_init_txid")?
            .to_string();

    let watchtower_proof =
        find_watchtower_task(&api_state.local_db, instance_id, graph_id, &payload.public_key)
            .await
            .api_error("POST_WATCHTOWER_PROOF_TASK_ERROR")?;

    match watchtower_proof {
        Some(watchtower_proof)
            if watchtower_proof.proof_state == ProofState::Proven.to_i64()
                && watchtower_proof.path_to_proof.is_some() =>
        {
            let proof_data = ProofData::load_proof_data(
                &watchtower_proof.path_to_proof.unwrap(),
                ProofType::Watchtower,
            );
            match ensure_proof_attested(&api_state, ProofType::Watchtower, &proof_data).await {
                Ok(_) => ok_response(WatchtowerProofResponse {
                    proof_data: Some(proof_data),
                    error: None,
                }),
                Err(err) => {
                    ok_response(WatchtowerProofResponse { proof_data: None, error: Some(err) })
                }
            }
        }
        Some(watchtower_proof) => ok_response(WatchtowerProofResponse {
            proof_data: None,
            error: Some(format!(
                "No proof is not ready, state {}, path:{:?}",
                watchtower_proof.proof_state, watchtower_proof.path_to_proof
            )),
        }),

        None => {
            add_watchtower_task(
                &api_state.local_db,
                instance_id,
                graph_id,
                payload.public_key,
                challenge_init_txid,
                payload.execution_layer_block_number,
            )
            .await
            .api_error("POST_WATCHTOWER_PROOF_TASK_ERROR")?;
            ok_response(WatchtowerProofResponse {
                proof_data: None,
                error: Some("No proof found".to_string()),
            })
        }
    }
}

#[axum::debug_handler]
pub(super) async fn update_watchtower_proof_task_timeout(
    State(api_state): State<Arc<ApiState>>,
    Json(payload): Json<WatchtowerProofTimeoutUpdateRequest>,
) -> ApiResult<WatchtowerProofTimeoutUpdateResponse> {
    let instance_id = InputValidator::validate_uuid(&payload.instance_id, "instance_id")?;
    let graph_id = InputValidator::validate_uuid(&payload.graph_id, "graph_id")?;
    match update_watchtower_task_state(
        &api_state.local_db,
        instance_id,
        graph_id,
        &payload.public_key,
        ProofState::New,
        ProofState::Failed,
    )
    .await
    {
        Ok(rows_affected) => ok_response(WatchtowerProofTimeoutUpdateResponse {
            instance_id: instance_id.to_string(),
            graph_id: graph_id.to_string(),
            public_key: payload.public_key.clone(),
            data: Some(format!("{rows_affected} rows affected")),
            error: None,
        }),
        Err(error) => ok_response(WatchtowerProofTimeoutUpdateResponse {
            instance_id: instance_id.to_string(),
            graph_id: graph_id.to_string(),
            public_key: payload.public_key.clone(),
            data: None,
            error: Some(format!("update error: {error}")),
        }),
    }
}
