pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/bitify.circom";

/*
 * Converts a field element (253 bits) to n 32-bit output elements where n <= 7
 * and n > 1
 */
template UnpackElement(n) {
    signal input in;
    signal output out[n];
    assert(n > 1);
    assert(n <= 7);

    // Convert input to bits
    component inputBits = Num2Bits_strict();
    inputBits.in <== in;

    component outputElements[n];
    for (var i = 0; i < n; i ++) {
        outputElements[i] = Bits2Num(32);
        for (var j = 0; j < 32; j ++) {
            outputElements[i].in[j] <== inputBits.out[((n - i - 1) * 32) + j];
        }
        out[i] <== outputElements[i].out;
    }
}
