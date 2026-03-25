CREATE TABLE IF NOT EXISTS part_stark_vk_attestation_batch
(
    id                                INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_tag                        TEXT   NOT NULL,
    zkm_version                       TEXT   NOT NULL,
    part_stark_vk_hash                TEXT   NOT NULL,
    sequencer_set_hash                TEXT   NOT NULL,
    sequencer_set_cosmos_block_height BIGINT NOT NULL,
    sequencer_set_goat_block_height   BIGINT NOT NULL,
    sequencer_set_size                BIGINT NOT NULL,
    threshold                         BIGINT NOT NULL,
    attestation_hash                  TEXT   NOT NULL,
    status                            TEXT   NOT NULL,
    bitcoin_txid                      TEXT,
    bitcoin_confirmed_height          BIGINT,
    locally_verified_at               BIGINT NOT NULL,
    bitcoin_confirmed_at              BIGINT,
    created_at                        BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_part_stark_vk_attestation_batch_query
    ON part_stark_vk_attestation_batch
        (domain_tag, zkm_version, part_stark_vk_hash, sequencer_set_hash, id DESC);

CREATE INDEX IF NOT EXISTS idx_part_stark_vk_attestation_batch_status
    ON part_stark_vk_attestation_batch(status, bitcoin_txid);

CREATE TABLE IF NOT EXISTS part_stark_vk_attestation_signature
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id     BIGINT NOT NULL,
    signer_pubkey TEXT NOT NULL,
    signature    TEXT   NOT NULL,
    created_at   BIGINT NOT NULL DEFAULT 0,
    FOREIGN KEY (batch_id) REFERENCES part_stark_vk_attestation_batch (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_part_stark_vk_attestation_signature_batch_signer
    ON part_stark_vk_attestation_signature(batch_id, signer_pubkey);

CREATE INDEX IF NOT EXISTS idx_part_stark_vk_attestation_signature_batch
    ON part_stark_vk_attestation_signature(batch_id);
