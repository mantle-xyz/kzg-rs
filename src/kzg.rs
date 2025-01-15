use alloc::vec::Vec;
use anyhow::{anyhow, Error};
use num::BigUint;
use rust_kzg_bn254::blob::Blob;
use rust_kzg_bn254::kzg::KZG;

// nitro code https://github.com/Layr-Labs/nitro/blob/14f09745b74321f91d1f702c3e7bb5eb7d0e49ce/arbitrator/prover/src/kzgbn254.rs#L30
fn compute_bn254_kzg_proof( blob: &[u8]) -> Result<Vec<u8>, Error> {
    let mut kzg = match KZG::setup(
        "resources/g1.32mb.point",
        "",
        "resources/g2.point.powerOf2",
        268435456,
        1024,
    ) {
        Ok(k) => k,
        Err(e) => return Err(anyhow!("cannot setup kzg {}", e)),
    };

    let input = Blob::new(blob);
    let input_poly = input.to_polynomial_eval_form();

    kzg.data_setup_custom(1, input.len().try_into().unwrap()).unwrap();

    let mut output = vec![0u8; 0];

    // TODO proxy should have returned the commitment, should compare with the result
    let commitment = match kzg.commit_eval_form(&input_poly) {
        Ok(c) => c,
        Err(e) => return Err(anyhow!("kzg.commit_eval_form {}", e)),
    };

    let commitment_x_bigint: BigUint = commitment.x.into();
    let commitment_y_bigint: BigUint = commitment.y.into();

    append_left_padded_biguint_be(&mut output, &commitment_x_bigint);
    append_left_padded_biguint_be(&mut output, &commitment_y_bigint);

    let proof = match kzg.compute_blob_proof(&input, &commitment) {
        Ok(p) => p,
        Err(e) => return Err(anyhow!("kzg.compute_blob_kzg_proof {}", e)),
    };
    let proof_x_bigint: BigUint = proof.x.into();
    let proof_y_bigint: BigUint = proof.y.into();

    append_left_padded_biguint_be(&mut output, &proof_x_bigint);
    append_left_padded_biguint_be(&mut output, &proof_y_bigint);

    Ok(output)
}

pub fn append_left_padded_biguint_be( vec: &mut Vec<u8>, biguint: &BigUint) {
    let bytes = biguint.to_bytes_be();
    let padding = 32 - bytes.len();
    vec.extend(std::iter::repeat(0).take(padding));
    vec.extend_from_slice(&bytes);
}