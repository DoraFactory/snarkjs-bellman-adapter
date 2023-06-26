pub mod parser_bls;
pub mod parser_bn;
pub mod types;
use ff::PrimeField as Fr;
pub use parser_bls::{parse_bls_proof, parse_bls_vkey};
pub use parser_bn::{parse_bn_proof, parse_bn_vkey};

use std::env;
pub use types::{ProofStr, VkeyStr};

#[test]
pub fn snark_proof_bellman_bls_verify() {
	let arg1_value = match env::var("CIRCUIT_DIR_NAME") {
		Ok(value) => {
			if value.is_empty() {
				eprintln!("Error: CIRCUIT_DIR_NAME arg is empty.");
				assert!(false);
				return;
			}
			value
		},
		Err(e) => {
			eprintln!("Error: Failed to get CIRCUIT_DIR_NAME: {}", e);
			assert!(false);
			return;
		},
	};

	let arg2_value = match env::var("PUBLIC_INPUT") {
		Ok(value) => {
			if value.is_empty() {
				eprintln!("Error: PUBLIC_INPUT arg is empty.");
				assert!(false);
				return;
			}
			value
		},
		Err(e) => {
			eprintln!("Error: Failed to get PUBLIC_INPUT: {}", e);
			assert!(false);
			return;
		},
	};

	println!("THE CIRCUIT YOU ARE TESTING IS : {}", arg1_value);
	println!("PUBLIC INPUT is : {}", arg2_value);

	let circuit_dir_name = arg1_value.as_str();
	let public_input = arg2_value.as_str();

	use bellman::groth16::{prepare_verifying_key, verify_proof};
	use bls12_381::Bls12;

	println!(">>>>start encode the uncompressed data to Affine<<<<<");

	let pof = parse_bls_proof::<Bls12>(circuit_dir_name);
	println!("proof is {:?}", pof);

	let verificationkey = parse_bls_vkey::<Bls12>(circuit_dir_name);

	let pvk = prepare_verifying_key(&verificationkey);

    // "33" is the public signal
	assert!(verify_proof(&pvk, &pof, &[Fr::from_str_vartime(public_input).unwrap()]).is_ok());

	println!(">>>>end verification<<<<<<<");
}



#[test]
pub fn snark_proof_bellman_bn_verify() {
	let arg1_value = match env::var("CIRCUIT_DIR_NAME") {
		Ok(value) => {
			if value.is_empty() {
				eprintln!("Error: CIRCUIT_DIR_NAME arg is empty.");
				assert!(false);
				return;
			}
			value
		},
		Err(e) => {
			eprintln!("Error: Failed to get CIRCUIT_DIR_NAME: {}", e);
			assert!(false);
			return;
		},
	};

	let arg2_value = match env::var("PUBLIC_INPUT") {
		Ok(value) => {
			if value.is_empty() {
				eprintln!("Error: PUBLIC_INPUT arg is empty.");
				assert!(false);
				return;
			}
			value
		},
		Err(e) => {
			eprintln!("Error: Failed to get PUBLIC_INPUT: {}", e);
			assert!(false);
			return;
		},
	};

	println!("THE CIRCUIT YOU ARE TESTING IS : {}", arg1_value);
	println!("PUBLIC INPUT is : {}", arg2_value);

	let circuit_dir_name = arg1_value.as_str();
	let public_input = arg2_value.as_str();

	use bellman_ce::groth16::{prepare_verifying_key, verify_proof};
	use pairing_ce::bn256::Bn256;
	use ff_ce::PrimeField as Frce;

	println!(">>>>start encode the uncompressed data to Affine<<<<<");

	let pof = parse_bn_proof::<Bn256>(circuit_dir_name);
	println!("proof is {:?}", pof);

	let verificationkey = parse_bn_vkey::<Bn256>(circuit_dir_name);

	let pvk = prepare_verifying_key(&verificationkey);

	assert!(verify_proof(
		&pvk,
		&pof,
		&[Frce::from_str(public_input).unwrap()]
	).unwrap());

	println!(">>>>end verification<<<<<<<");
}
