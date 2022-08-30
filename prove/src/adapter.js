
import fs from "fs";
import path from "path";
import * as curves from "../utils/curve.js";
import { utils } from "ffjavascript";
const { unstringifyBigInts } = utils;

const adaptToUncompressed = async (verificationKeyName, proofName) => {

    const verificationKey = JSON.parse(fs.readFileSync(verificationKeyName, "utf8"));
    const pof = JSON.parse(fs.readFileSync(proofName, "utf8"));

    // from object to u8 array
    const vkey = unstringifyBigInts(verificationKey);
    const proof = unstringifyBigInts(pof);

    const curve = await curves.getCurveFromName(vkey.curve);

    console.log(curve);

    console.log("这是");
    console.log(curve.G1.fromObject(proof.pi_a));
    
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

    fs.writeFileSync(path.resolve("../../circuit/proof_uncompressed.json"), JSON.stringify(uncompressed_proof));
    fs.writeFileSync(path.resolve("../../circuit/vkey_uncompressed.json"), JSON.stringify(uncompressed_vkey));

}


adaptToUncompressed("../../circuit/verification_key.json", "../../circuit/proof.json")