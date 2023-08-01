pragma circom 2.0.0;

include "../hasherPoseidon.circom";

template ZeroRoot(depth) {
    signal output out;

    component hashers[depth];
    signal zeros[depth + 1];

    zeros[0] <== 0;

    for (var i = 0; i < depth; i ++) {
        hashers[i] = Hasher5();
        for (var j = 0; j < 5; j ++){
            hashers[i].in[j] <== zeros[i];
        }
        zeros[i + 1] <== hashers[i].hash;
    }


    out <== zeros[depth];
}

