use zkm_verifier::{Groth16Verifier, IMM_GROTH16_VK_BYTES};

pub fn verify_groth16_proof(
    proof: &[u8],
    zkm_public_values: &[u8],
    zkm_vk_hash: &[u8],
    zkm_version: &str,
) -> Result<(), String> {
    let groth16_vk = *IMM_GROTH16_VK_BYTES;
    let zkm_vk_hash = String::from_utf8(zkm_vk_hash.to_vec()).map_err(|e| e.to_string())?;
    let part_stark_vk = Groth16Verifier::get_part_stark_vk(zkm_version);

    match Groth16Verifier::verify_by_imm_groth16_vk(
        proof,
        zkm_public_values,
        &zkm_vk_hash,
        groth16_vk,
        part_stark_vk,
    ) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("Verify Groth16 proof, err: {err:?}")),
    }
}
