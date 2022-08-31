// For randomness (during paramgen and proof generation)
use rand::thread_rng;

// Bring in some tools for using finite fiels
use ff::Field;

// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use bls12_381::{Bls12, Scalar};

// We're going to use the Groth16 proving system.
use bellman::groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof};

mod circuit;
use circuit::*;

mod adapter;
// use adapter::snark_proof_bellman_verify;

fn main() {
    // step1
    let mut rng = thread_rng();
    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    println!("Creating parameters...");

    // Create parameters for our circuit
    let params = {
        let c = MiMCDemo {
            xl: None,
            xr: None,
            constants: &constants,
        };

        generate_random_parameters::<Bls12, _, _>(c, &mut rng).unwrap()
    };


    // step2 
    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");
    let xl = Scalar::random(&mut rng);
    let xr = Scalar::random(&mut rng);
    
    let image = mimc(xl, xr, &constants);

    // Create an instance of our circuit (with the
    // witness)
    let c = MiMCDemo {
        xl: Some(xl),
        xr: Some(xr), 
        constants: &constants,
    };

    // step3
    // Create a groth16 proof with our parameters.
    let proof = create_random_proof(c, &params, &mut rng).unwrap();

    // step4
    // if verification passed, return ()
    assert!(verify_proof(&pvk, &proof, &[image]).is_ok());

}
