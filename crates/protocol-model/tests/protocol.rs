use protocol_model::{
    GraphKey, GraphObservation, GraphStatus, OutPointRef, ProtocolEvent, ProtocolState, SpendKind,
    TransitionError, apply_event, derive_graph_status,
};
use std::str::FromStr;

fn key() -> GraphKey {
    GraphKey::new("instance-1", "graph-1", 7)
}

#[test]
fn frontend_display_statuses_are_not_protocol_states() {
    for status in
        ["Created", "Presigned", "L2Recorded", "OperatorKickOffing", "Challenging", "Disproving"]
    {
        assert!(GraphStatus::from_str(status).is_err());
    }
}

fn ready_state() -> ProtocolState {
    let mut state = ProtocolState::new(2);
    for signer in ["committee-a", "committee-b"] {
        state = apply_event(
            &state,
            ProtocolEvent::CommitteeSigned {
                key: key(),
                signer: signer.into(),
                graph_hash: "hash-1".into(),
                valid: true,
            },
        )
        .unwrap();
    }
    state = apply_event(
        &state,
        ProtocolEvent::FinalizeGraph { key: key(), graph_hash: "hash-1".into() },
    )
    .unwrap();
    state = apply_event(&state, ProtocolEvent::GoatGraphRecorded { key: key() }).unwrap();
    state = apply_event(&state, ProtocolEvent::PreKickoffConfirmed { key: key() }).unwrap();
    apply_event(
        &state,
        ProtocolEvent::KickoffConfirmed { key: key(), input: OutPointRef::new("prekickoff", 1) },
    )
    .unwrap()
}

#[test]
fn graph_requires_all_valid_committee_signatures() {
    let state = ProtocolState::new(2);
    let state = apply_event(
        &state,
        ProtocolEvent::CommitteeSigned {
            key: key(),
            signer: "committee-a".into(),
            graph_hash: "hash-1".into(),
            valid: true,
        },
    )
    .unwrap();

    assert_eq!(
        apply_event(
            &state,
            ProtocolEvent::FinalizeGraph { key: key(), graph_hash: "hash-1".into() }
        ),
        Err(TransitionError::InsufficientCommitteeSignatures)
    );
}

#[test]
fn honest_committee_signature_cannot_equivocate_or_replay_across_graphs() {
    let event = ProtocolEvent::CommitteeSigned {
        key: key(),
        signer: "committee-a".into(),
        graph_hash: "hash-1".into(),
        valid: true,
    };
    let state = apply_event(&ProtocolState::new(2), event.clone()).unwrap();
    assert_eq!(apply_event(&state, event).unwrap(), state);

    let mut other = key();
    other.graph_id = "graph-2".into();
    assert_eq!(
        apply_event(
            &state,
            ProtocolEvent::CommitteeSigned {
                key: other,
                signer: "committee-a".into(),
                graph_hash: "hash-1".into(),
                valid: true,
            }
        ),
        Err(TransitionError::CrossGraphReplay)
    );

    assert_eq!(
        apply_event(
            &state,
            ProtocolEvent::CommitteeSigned {
                key: key(),
                signer: "committee-a".into(),
                graph_hash: "hash-2".into(),
                valid: true,
            }
        ),
        Err(TransitionError::ConflictingCommitteeSignature)
    );
}

#[test]
fn invalid_signature_and_invalid_proof_are_rejected() {
    assert_eq!(
        apply_event(
            &ProtocolState::new(2),
            ProtocolEvent::CommitteeSigned {
                key: key(),
                signer: "byzantine".into(),
                graph_hash: "hash-1".into(),
                valid: false,
            }
        ),
        Err(TransitionError::InvalidSignature)
    );

    let state = apply_event(
        &ready_state(),
        ProtocolEvent::ChallengeConfirmed { key: key(), input: OutPointRef::new("kickoff-a", 0) },
    )
    .unwrap();
    assert_eq!(
        apply_event(&state, ProtocolEvent::OperatorProofAccepted { key: key(), valid: false }),
        Err(TransitionError::InvalidProof)
    );
}

#[test]
fn take1_requires_kickoff_timelock_and_competes_with_challenge() {
    let state = ready_state();
    let take1 = ProtocolEvent::Take1Confirmed {
        key: key(),
        input: OutPointRef::new("kickoff-a", 0),
        timelock_satisfied: false,
    };
    assert_eq!(apply_event(&state, take1), Err(TransitionError::TimelockNotSatisfied));

    let challenged = apply_event(
        &state,
        ProtocolEvent::ChallengeConfirmed { key: key(), input: OutPointRef::new("kickoff-a", 0) },
    )
    .unwrap();
    assert_eq!(
        apply_event(
            &challenged,
            ProtocolEvent::Take1Confirmed {
                key: key(),
                input: OutPointRef::new("kickoff-a", 0),
                timelock_satisfied: true,
            }
        ),
        Err(TransitionError::OutPointAlreadySpent)
    );
}

#[test]
fn take2_requires_challenge_valid_proof_and_timelock_and_competes_with_disprove() {
    let state = ready_state();
    assert_eq!(
        apply_event(
            &state,
            ProtocolEvent::Take2Confirmed {
                key: key(),
                input: OutPointRef::new("connector-d", 0),
                timelock_satisfied: true,
            }
        ),
        Err(TransitionError::MissingPrerequisite)
    );

    let state = apply_event(
        &state,
        ProtocolEvent::ChallengeConfirmed { key: key(), input: OutPointRef::new("kickoff-a", 0) },
    )
    .unwrap();
    let state =
        apply_event(&state, ProtocolEvent::OperatorProofAccepted { key: key(), valid: true })
            .unwrap();
    let disproved = apply_event(
        &state,
        ProtocolEvent::DisproveConfirmed { key: key(), input: OutPointRef::new("connector-d", 0) },
    )
    .unwrap();
    assert_eq!(disproved.graph(&key()).unwrap().status, GraphStatus::Disprove);
    assert_eq!(
        apply_event(
            &disproved,
            ProtocolEvent::Take2Confirmed {
                key: key(),
                input: OutPointRef::new("connector-d", 0),
                timelock_satisfied: true,
            }
        ),
        Err(TransitionError::OutPointAlreadySpent)
    );
}

#[test]
fn pegin_confirm_cancel_and_double_mint_are_exclusive() {
    let deposit = OutPointRef::new("deposit", 0);
    let state = apply_event(
        &ProtocolState::new(1),
        ProtocolEvent::PeginConfirmed { instance_id: "instance-1".into(), input: deposit.clone() },
    )
    .unwrap();
    assert_eq!(
        apply_event(
            &state,
            ProtocolEvent::PeginCancelled { instance_id: "instance-1".into(), input: deposit }
        ),
        Err(TransitionError::ConflictingTerminal)
    );
    assert_eq!(
        apply_event(
            &state,
            ProtocolEvent::PeginCancelled {
                instance_id: "instance-1".into(),
                input: OutPointRef::new("wrong-deposit", 0),
            }
        ),
        Err(TransitionError::ConflictingTerminal)
    );
    let state =
        apply_event(&state, ProtocolEvent::Minted { instance_id: "instance-1".into() }).unwrap();
    assert_eq!(
        apply_event(&state, ProtocolEvent::Minted { instance_id: "instance-1".into() }),
        Ok(state)
    );
}

#[test]
fn two_graphs_cannot_claim_the_same_kickoff_input() {
    let state = ready_state();
    let mut second = key();
    second.graph_id = "graph-2".into();
    second.graph_nonce = 8;
    let state = apply_event(&state, ProtocolEvent::CreateGraph { key: second.clone() }).unwrap();
    let mut state = state;
    state.graphs.get_mut(&second).unwrap().status = GraphStatus::PreKickoff;
    assert_eq!(
        apply_event(
            &state,
            ProtocolEvent::KickoffConfirmed {
                key: second,
                input: OutPointRef::new("prekickoff", 1),
            }
        ),
        Err(TransitionError::OutPointAlreadySpent)
    );
}

#[test]
fn rescan_derivation_is_deterministic_and_idempotent() {
    let state = ProtocolState::new(1).with_graph(key(), GraphStatus::OperatorDataPushed);
    let observation = GraphObservation {
        key: key(),
        committee_pre_signed: true,
        goat_graph_recorded: true,
        goat_graph_obsoleted: false,
        prekickoff_confirmed: true,
        prekickoff_spend: SpendKind::Expected,
        guardian_disprove: false,
        connector_a_spend: SpendKind::Expected,
        take1_timelock_satisfied: true,
        challenge_confirmed: false,
        operator_proof_valid: false,
        connector_d_spend: SpendKind::Unspent,
        verifier_disprove: false,
        take2_confirmed: false,
        take2_timelock_satisfied: false,
    };
    assert_eq!(derive_graph_status(&state, &observation).unwrap(), GraphStatus::OperatorTake1);
    assert_eq!(derive_graph_status(&state, &observation).unwrap(), GraphStatus::OperatorTake1);
}

#[test]
fn protocol_state_has_stable_json_representation() {
    let state = ready_state();
    let encoded = serde_json::to_string(&state).unwrap();
    let decoded: ProtocolState = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, state);
}
