use bellman::groth16::{
    prepare_verifying_key, verify_proof, Proof, VerifyingKey,
};
use pairing::{Engine};
use bls12_381::{Bls12, G1Affine, G2Affine};
use ff::PrimeFieldBits;
use super::{ProofStr, VkeyStr};
use std::str::FromStr;
use std::path::PathBuf;
use std::fs;

pub fn parse_proof<E>() -> Proof<E>
where
    E: Engine<G1Affine = G1Affine, G2Affine = G2Affine>,
{
    let mut config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    config_path.pop();
    config_path.push("circuit");
    config_path.push("proof_uncompressed.json");
    let ff = fs::read_to_string(config_path.as_path()).unwrap();
    let pof: ProofStr = serde_json::from_str(&ff).unwrap();
    let pi_a = pof.pi_a;
    let pi_b = pof.pi_b;
    let pi_c = pof.pi_c;

    let mut a_arr: [u8; 96] = [0; 96];
    let mut b_arr: [u8; 192] = [0; 192];
    let mut c_arr: [u8; 96] = [0; 96];

    for i in 0..pi_a.len() {
        a_arr[i] = pi_a[i];
    }

    for i in 0..pi_b.len() {
        b_arr[i] = pi_b[i];
    }

    for i in 0..pi_c.len() {
        c_arr[i] = pi_c[i];
    }

    let pia_affine = G1Affine::from_uncompressed(&a_arr).unwrap();
    let pib_affine = G2Affine::from_uncompressed(&b_arr).unwrap();
    let pic_affine = G1Affine::from_uncompressed(&c_arr).unwrap();

    Proof{
        a: pia_affine,
        b: pib_affine,
        c: pic_affine,
    }
}

pub fn parse_vkey<E>() -> VerifyingKey<E>
where
E: Engine<G1Affine = G1Affine, G2Affine = G2Affine>,
{
    let mut config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    config_path.pop();
    config_path.push("circuit");
    config_path.push("vkey_uncompressed.json");
    let ff = fs::read_to_string(config_path.as_path()).unwrap();
    let vk: VkeyStr = serde_json::from_str(&ff).unwrap();
    let vk_alpha_1 = vk.alpha_1;
    let vk_beta_2 = vk.beta_2;
    let vk_gamma_2 = vk.gamma_2;
    let vk_delta_2 =  vk.delta_2;
    let vk_ic = vk.ic;

    let mut alpha1: [u8; 96] = [0; 96];
    let mut beta2: [u8; 192] = [0; 192];
    let mut gamma2: [u8; 192] = [0; 192];
    let mut delta2: [u8; 192] = [0; 192];
    let mut ic_0: [u8; 96] = [0; 96];
    let mut ic_1: [u8; 96] = [0; 96];
    let mut ic = Vec::new();

    for i in 0..vk_alpha_1.len() {
        alpha1[i] = vk_alpha_1[i];
    }

    for i in 0..vk_beta_2.len() {
        beta2[i] = vk_beta_2[i];
    }

    for i in 0..vk_gamma_2.len() {
        gamma2[i] = vk_gamma_2[i];
    }

    for i in 0..vk_delta_2.len() {
        delta2[i] = vk_delta_2[i];
    }

    for i in 0..vk_ic[0].len() {
        ic_0[i] = vk_ic[0][i];
    }

    for i in 0..vk_ic[1].len() {
        ic_1[i] = vk_ic[1][i];
    }

    let alpha1_affine = G1Affine::from_uncompressed(&alpha1).unwrap();
    let beta2_affine = G2Affine::from_uncompressed(&beta2).unwrap();
    let gamma2_affine = G2Affine::from_uncompressed(&gamma2).unwrap();
    let delta2_affine = G2Affine::from_uncompressed(&delta2).unwrap();
    let ic0_affine = G1Affine::from_uncompressed(&ic_0).unwrap();
    let ic1_affine = G1Affine::from_uncompressed(&ic_1).unwrap();
    ic.push(ic0_affine);
    ic.push(ic1_affine);

    VerifyingKey{
        alpha_g1: alpha1_affine,
        beta_g1: G1Affine::identity(),
        beta_g2: beta2_affine,
        gamma_g2: gamma2_affine,
        delta_g1: G1Affine::identity(),
        delta_g2: delta2_affine,
        ic,
    }
}