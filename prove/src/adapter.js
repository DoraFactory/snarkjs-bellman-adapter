
import fs from "fs";
import path from "path";
import * as curves from "../utils/curve.js";
import { utils } from "ffjavascript";
const { unstringifyBigInts } = utils;

if (process.argv.length < 3) {
    console.error("Usage: node adapter.js <circuit-dir-name>");
    process.exit(1);
}
const circuit_dir_name = process.argv[2];

const adaptToUncompressed = async (verificationKeyName, proofName) => {

    const verificationKey = JSON.parse(fs.readFileSync(verificationKeyName, "utf8"));
    const pof = JSON.parse(fs.readFileSync(proofName, "utf8"));

    // from object to u8 array
    const vkey = unstringifyBigInts(verificationKey);
    const proof = unstringifyBigInts(pof);

    const curve = await curves.getCurveFromName(vkey.curve);

    // convert u8 array(little-endian order)to uncompressed type(big-endian order and on bls12_381 curve) 
    // which can be convert into Affine type in bellman
    const pi_a = curve.G1.toUncompressed(curve.G1.fromObject(proof.pi_a));
    const pi_b = curve.G2.toUncompressed(curve.G2.fromObject(proof.pi_b));
    const pi_c = curve.G1.toUncompressed(curve.G1.fromObject(proof.pi_c));

    const vk_alpha_1 = curve.G1.toUncompressed(curve.G1.fromObject(vkey.vk_alpha_1));
    const vk_beta_2 = curve.G2.toUncompressed(curve.G2.fromObject(vkey.vk_beta_2));
    const vk_gamma_2 = curve.G2.toUncompressed(curve.G2.fromObject(vkey.vk_gamma_2));
    const vk_delta_2 = curve.G2.toUncompressed(curve.G2.fromObject(vkey.vk_delta_2));
    const ic_0 = curve.G1.toUncompressed(curve.G1.fromObject(vkey.IC[0]));
    const ic_1 = curve.G1.toUncompressed(curve.G1.fromObject(vkey.IC[1]));

    let ic = [];
    ic.push(Array.from(ic_0));
    ic.push(Array.from(ic_1));

    let uncompressed_proof = {};
    let uncompressed_vkey = {};
    uncompressed_proof.pi_a = Array.from(pi_a);
    uncompressed_proof.pi_b = Array.from(pi_b);
    uncompressed_proof.pi_c = Array.from(pi_c);

    uncompressed_vkey.alpha_1 = Array.from(vk_alpha_1);
    uncompressed_vkey.beta_2 = Array.from(vk_beta_2);
    uncompressed_vkey.gamma_2 = Array.from(vk_gamma_2);
    uncompressed_vkey.delta_2 = Array.from(vk_delta_2);
    uncompressed_vkey.ic = ic;
    
    let hex_proof = {};
    let hex_vkey = {};
    hex_proof.pi_a = '0x'+Bytes2Str( uncompressed_proof.pi_a)
    hex_proof.pi_b = '0x'+Bytes2Str( uncompressed_proof.pi_b)
    hex_proof.pi_c = '0x'+Bytes2Str( uncompressed_proof.pi_c)
    hex_vkey.alpha_1 = '0x'+Bytes2Str( uncompressed_vkey.alpha_1)
    hex_vkey.beta_2 = '0x'+Bytes2Str( uncompressed_vkey.beta_2)
    hex_vkey.gamma_2 = '0x'+Bytes2Str( uncompressed_vkey.gamma_2)
    hex_vkey.delta_2 = '0x'+Bytes2Str( uncompressed_vkey.delta_2)
    hex_vkey.ic0 = '0x'+Bytes2Str( uncompressed_vkey.ic[0])
    hex_vkey.ic1 = '0x'+Bytes2Str( uncompressed_vkey.ic[1])

    fs.writeFileSync(path.resolve(`../../circuit/${circuit_dir_name}/proof_uncompressed.json`), JSON.stringify(uncompressed_proof));
    fs.writeFileSync(path.resolve(`../../circuit/${circuit_dir_name}/vkey_uncompressed.json`), JSON.stringify(uncompressed_vkey));
    
    fs.writeFileSync(path.resolve(`../../circuit/${circuit_dir_name}/proof_hex.json`), JSON.stringify(hex_proof));
    fs.writeFileSync(path.resolve(`../../circuit/${circuit_dir_name}/vkey_hex.json`), JSON.stringify(hex_vkey));

    console.log(`generate uncompressed proof and verification data successfully!`);
    process.exit();
}

function Bytes2Str(arr) {
    let str = "";
    for (let i = 0; i < arr.length; i++) {
        let tmp = arr[i].toString(16);
        if (tmp.length == 1) {
            tmp = "0" + tmp;
        }
        str += tmp;
    }
    return str;
}

adaptToUncompressed(`../../circuit/${circuit_dir_name}/verification_key.json`, `../../circuit/${circuit_dir_name}/proof.json`)
