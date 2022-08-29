
pub mod parser;
pub mod types;
use super::circuit::{MiMCDemo, MIMC_ROUNDS};
use bellman::Circuit;
use ff::PrimeField;
use ff::{Field, PrimeField as Fr};
use group::{ Curve, Group, Wnaf, WnafGroup};
use pairing::Engine;
use rand::{thread_rng, RngCore};
use std::fs;
use std::fs::File;
use std::io::{Read, BufRead};
use std::ops::Neg;
pub use parser::{parse_proof, parse_vkey};
pub use types::{ProofStr, VkeyStr};

#[test]
pub fn snark_proof_bellman_verify() {
    use bellman::groth16::{
        prepare_verifying_key, verify_proof, Proof, VerifyingKey,
    };
    use bls12_381::{Bls12, G1Affine, G2Affine};

    println!(">>>>start encode the uncompressed data to Affine<<<<<");

    let pof =  parse_proof::<Bls12>();

    let verificationkey =  parse_vkey::<Bls12>();

    let pvk =  prepare_verifying_key(&verificationkey);

    assert!(verify_proof(&pvk, &pof, &[Fr::from_str_vartime("33").unwrap()]).is_ok());

    println!(">>>>end verification<<<<<<<");

}