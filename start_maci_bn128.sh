#!/bin/sh

compile_and_ts_and_witness() {
  circuit_dir_name=$1

  cd ${circuit_dir_name}

  generate inputs by js
  mkdir inputs
  npm install
  node js/maci.test.js inputs

  #compile circuits
  mkdir -p build/r1cs

  echo $(date +"%T") "compile the circuit into r1cs, wasm and sym"
  itime="$(date -u +%s)"
  circom circuits/prod/msg.circom --r1cs --wasm --sym -o build/r1cs
  circom circuits/prod/tally.circom --r1cs --wasm --sym -o build/r1cs
  ftime="$(date -u +%s)"
  echo "	($(($(date -u +%s)-$itime))s)"

  # create zkey
  echo $(date +"%T") "start create zkey"
  mkdir -p build/zkey
  snarkjs g16s build/r1cs/msg.r1cs ../../ptau/powersOfTau28_hez_final_22.ptau build/zkey/msg_0.zkey
  snarkjs g16s build/r1cs/tally.r1cs ../../ptau/powersOfTau28_hez_final_22.ptau build/zkey/tally_0.zkey

  # output verification key
  echo $(date +"%T") "output verification key"
  mkdir -p build/verification_key/msg
  mkdir -p build/verification_key/tally
  snarkjs zkc build/zkey/msg_0.zkey build/zkey/msg_1.zkey --name="DoraHacks" -v
  snarkjs zkev build/zkey/msg_1.zkey build/verification_key/msg/verification_key.json

  snarkjs zkc build/zkey/tally_0.zkey build/zkey/tally_1.zkey --name="DoraHacks" -v
  snarkjs zkev build/zkey/tally_1.zkey build/verification_key/tally/verification_key.json

  # generate witness
  echo $(date +"%T") "start generate witness"
  mkdir -p build/wtns

  node "build/r1cs/msg_js/generate_witness.js" "build/r1cs//msg_js/msg.wasm" "./inputs/msg-input_0000.json" "./build/wtns/msg.wtns"
  node "build/r1cs/tally_js/generate_witness.js" "build/r1cs/tally_js/tally.wasm" "./inputs/tally-input_0000.json" "./build/wtns/tally.wtns"

 # generate public and proof
 echo $(date +"%T") "start generate proof"
 mkdir -p build/proof/msg
 mkdir -p build/proof/tally
 mkdir -p build/public
 snarkjs g16p "build/zkey/msg_1.zkey" "build/wtns/msg.wtns" "build/proof/msg/proof.json" build/public/msg-public.json
 snarkjs g16p "build/zkey/tally_1.zkey" "build/wtns/tally.wtns" "build/proof/tally/proof.json" build/public/tally-public.json

 # verify proof by snarkjs
 echo $(date +"%T") "start verify the msg proof"
 snarkjs groth16 verify build/verification_key/msg/verification_key.json build/public/msg-public.json build/proof/msg/proof.json
 echo $(date +"%T") "start verify the tally proof"
 snarkjs groth16 verify build/verification_key/tally/verification_key.json build/public/tally-public.json build/proof/tally/proof.json


 # start generate final proof
 echo $(date +"%T") "start transform the proof data format"
 mkdir -p build/final_proof/msg
 mkdir -p build/final_proof/tally
 mkdir -p build/final_verification_key/msg
 mkdir -p build/final_verification_key/tally
 cd ../../prove && npm install && cd src && node adapt_maci.js msg && node adapt_maci.js tally
 echo "everything is ok"

}

if [ $# -eq 0 ]; then
  echo "Usage: $0 <circuit_dir_name>"
  exit 1
fi

circuit_dir_name=$1
echo "compile & trustesetup for circuit"
cd circuit/
compile_and_ts_and_witness "$circuit_dir_name"
