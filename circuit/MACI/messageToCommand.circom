pragma circom 2.0.0;

include "./ecdh.circom";
include "./unpackElement.circom";
include "./lib/poseidonDecrypt.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template Uint32to96() {
    signal input in[3];
    signal output out;

    out <== in[2] + in[1] * 4294967296 + in[0] * 18446744073709552000;
}

template MessageToCommand() {
    var MSG_LENGTH = 7;
    var CMD_LENGTH = 6;
    var PACKED_CMD_LENGTH = 3;

    signal input message[MSG_LENGTH];
    signal input encPrivKey;
    signal input encPubKey[2];

    signal output stateIndex;
    signal output voteOptionIndex;
    signal output newVoteWeight;
    signal output nonce;
    signal output newPubKey[2];
    signal output sigR8[2];
    signal output sigS;
    signal output packedCommandOut[PACKED_CMD_LENGTH];

    component ecdh = Ecdh();
    ecdh.privKey <== encPrivKey;
    ecdh.pubKey[0] <== encPubKey[0];
    ecdh.pubKey[1] <== encPubKey[1];

    component decryptor = PoseidonDecryptWithoutCheck(CMD_LENGTH);
    decryptor.key[0] <== ecdh.sharedKey[0];
    decryptor.key[1] <== ecdh.sharedKey[1];
    decryptor.nonce <== 0;
    for (var i = 0; i < MSG_LENGTH; i++) {
        decryptor.ciphertext[i] <== message[i];
    }

    component unpack = UnpackElement(6);
    unpack.in <== decryptor.decrypted[0];

    nonce <== unpack.out[5];
    stateIndex <== unpack.out[4];
    voteOptionIndex <== unpack.out[3];

    component computeVoteWeight = Uint32to96();
    for (var i = 0; i < 3; i ++) {
        computeVoteWeight.in[i] <== unpack.out[i];
    }
    newVoteWeight <== computeVoteWeight.out;

    newPubKey[0] <== decryptor.decrypted[1];
    newPubKey[1] <== decryptor.decrypted[2];

    sigR8[0] <== decryptor.decrypted[3];
    sigR8[1] <== decryptor.decrypted[4];
    sigS <== decryptor.decrypted[5];

    for (var i = 0; i < PACKED_CMD_LENGTH; i ++) {
        packedCommandOut[i] <== decryptor.decrypted[i];
    }

    signal output sharedKey[2];
    sharedKey[0] <== ecdh.sharedKey[0];
    sharedKey[1] <== ecdh.sharedKey[1];
}
