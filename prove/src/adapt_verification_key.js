import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "../utils/zkey_utils.js";
import { getCurveFromQ as getCurve } from "../utils/curve.js";
import fs from "fs";
import path from "path";

const generate_verification_key = async (zkeyName) => {

    const { fd, sections } = await binFileUtils.readBinFile(zkeyName, "zkey", 2);
    const zkey = await zkeyUtils.readHeader(fd, sections);
    let res;
    if (zkey.protocol == "groth16") {
        res = await groth16Vk(zkey, fd, sections);
    } else {
        throw new Error("zkey file is not groth16");
    }
    await fd.close();
    return res;
}


async function groth16Vk (zkey, fd, sections) {
    const curve = await getCurve(zkey.q);
    const sG1 = curve.G1.F.n8 * 2;

    // Read IC Section
    ///////////
    await binFileUtils.startReadUniqueSection(fd, sections, 3);
    let ic = [];
    for (let i = 0; i <= zkey.nPublic; i++) {
        const buff = await fd.read(sG1);
        const P = Array.from(curve.G1.toUncompressed(buff));
        ic.push(P);
    }
    await binFileUtils.endReadSection(fd);

    let alpha1_uncompressed = curve.G1.toUncompressed(zkey.vk_alpha_1);
    let beta2_uncompressed = curve.G2.toUncompressed(zkey.vk_beta_2);
    let gamma2_uncompressed = curve.G2.toUncompressed(zkey.vk_gamma_2);
    let delta2_uncompressed = curve.G2.toUncompressed(zkey.vk_delta_2);

    let vkey = {};
    vkey.alpha_1 = Array.from(alpha1_uncompressed);
    vkey.beta_2 = Array.from(beta2_uncompressed);
    vkey.gamma_2 = Array.from(gamma2_uncompressed);
    vkey.delta_2 = Array.from(delta2_uncompressed);
    vkey.ic = ic;
    console.log(vkey);
    fs.writeFileSync(path.resolve("../../circuit/vkey_uncompressed.json"), JSON.stringify(vkey));
}

generate_verification_key("../../circuit/circuit_final.zkey")