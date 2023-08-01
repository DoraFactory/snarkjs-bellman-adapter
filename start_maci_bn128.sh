#!/bin/sh

compile_and_ts_and_witness() {
  circuit_dir_name=$1

  cd ${circuit_dir_name}

  # generate inputs by js
  mkdir inputs
  node js/maci.test.js ../inputs

  #compile circuits
  mkdir -r build/r1cs

  echo $(date +"%T") "coompile the circuit into r1cs, wasm and sym"
  itime="$(date -u +%s)"
  circom prod/msg.circom --r1cs --wasm --sym -o build/r1cs
  circom prod/tally.circom --r1cs --wasm --sym -o build/r1cs
  ftime="$(date -u +%s)"
  echo "	($(($(date -u +%s)-$itime))s)"

  # create zkey
  mkdir -r build/zkey
  snarkjs g16s build/r1cs/msg.r1cs ptau/powersOfTau28_hez_final_22.ptau build/zkey/msg_0.zkey
  snarkjs g16s build/r1cs/tally.r1cs ptau/powersOfTau28_hez_final_22.ptau build/zkey/tally_0.zkey

  # output verification key
  mkdir -r build/verification_key
  snarkjs zkc build/zkey/msg_0.zkey build/zkey/msg_1.zkey --name="DoraHacks" -v
  snarkjs zkev build/zkey/msg_1.zkey build/verification_key/msg_verification_key.json

  snarkjs zkc build/zkey/tally_0.zkey build/zkey/tally_1.zkey --name="DoraHacks" -v
  snarkjs zkev build/zkey/tally_1.zkey build/verification_key/tally_verification_key.json

  # generate witness
  mkdir -r build/proof
  mkdir -r build/wtns

  node "./msg_js/generate_witness.js" "./msg_js/circuit.wasm" "./inputs/msg-input_0000.json" "./wtns/msg.wtns"
  node "./tally_js/generate_witness.js" "./tally_js/circuit.wasm" "./inputs/tally-input_0000.json" "./wtns/tally.wtns"

 # generate public and proof
 snarkjs g16p "./zkey/msg_1.zkey" "./wtns/msg.wtns" "./proof/msg_proof.json" msg-public.json
 snarkjs g16p "./zkey/tally_1.zkey" "./wtns/msg.wtns" "./proof/tally_proof.json" tally-public.json

 # verify proof by snarkjs
 #snarkjs groth16 verify verification_key.json public.json proof.json

}

if [ $# -eq 0 ]; then
  echo "Usage: $0 <circuit_dir_name>"
  exit 1
fi

circuit_dir_name=$1
echo "compile & trustesetup for circuit"
cd circuit/
compile_and_ts_and_witness "$circuit_dir_name"
