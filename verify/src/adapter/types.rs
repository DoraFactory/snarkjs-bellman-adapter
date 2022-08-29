use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize)]
pub struct ProofStr {
    pub pi_a: Vec<u8>,
    pub pi_b: Vec<u8>,
    pub pi_c: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct VkeyStr {
    pub alpha_1: Vec<u8>,
    pub beta_2: Vec<u8>,
    pub gamma_2: Vec<u8>,
    pub delta_2: Vec<u8>,
    pub ic: Vec<Vec<u8>>,
}
