pragma circom 2.0.0;

include "./hasherSha256.circom";
include "./messageHasher.circom";
include "./messageToCommand.circom";
include "./privToPubKey.circom";
include "./stateLeafTransformer.circom";
include "./trees/incrementalQuinTree.circom";
include "./trees/zeroRoot.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

/*
 * Proves the correctness of processing a batch of messages.
 */
template ProcessMessages(
    stateTreeDepth,
    voteOptionTreeDepth,
    batchSize
) {
    // stateTreeDepth: the depth of the state tree
    // voteOptionTreeDepth: depth of the vote option tree
    // batchSize: number of messages processed at one time

    assert(stateTreeDepth > 0);
    assert(voteOptionTreeDepth > 0);
    assert(batchSize > 0);

    var TREE_ARITY = 5;

    var MSG_LENGTH = 7;
    var PACKED_CMD_LENGTH = 3;

    // var BALLOT_LENGTH = 2;
    // var BALLOT_NONCE_IDX = 0;
    // var BALLOT_VO_ROOT_IDX = 1;

    var STATE_LEAF_LENGTH = 5;

    var STATE_LEAF_PUB_X_IDX = 0;
    var STATE_LEAF_PUB_Y_IDX = 1;
    var STATE_LEAF_VOICE_CREDIT_BALANCE_IDX = 2;
    var STATE_LEAF_VO_ROOT_IDX = 3;
    var STATE_LEAF_NONCE_IDX = 4;
    
    // Note that we sha256 hash some values from the contract, pass in the hash
    // as a public input, and pass in said values as private inputs. This saves
    // a lot of gas for the verifier at the cost of constraints for the prover.

    //  ----------------------------------------------------------------------- 
    // The only public input, which is the SHA256 hash of a values provided
    // by the contract
    signal input inputHash;
    signal input packedVals;

    signal numSignUps;
    signal maxVoteOptions;

    signal input batchStartHash;
    signal input batchEndHash;

    // The coordinator's private key
    signal input coordPrivKey;

    // The cooordinator's public key from the contract.
    signal input coordPubKey[2];

    // The messages
    signal input msgs[batchSize][MSG_LENGTH];

    // The ECDH public key per message
    signal input encPubKeys[batchSize][2];

    // The state root before it is processed
    signal input currentStateRoot;

    // The state leaves upon which messages are applied.
    //     transform(currentStateLeaf[4], message5) => newStateLeaf4
    //     transform(currentStateLeaf[3], message4) => newStateLeaf3
    //     transform(currentStateLeaf[2], message3) => newStateLeaf2
    //     transform(currentStateLeaf[1], message1) => newStateLeaf1
    //     transform(currentStateLeaf[0], message0) => newStateLeaf0
    //     ...
    // Likewise, currentStateLeavesPathElements contains the Merkle path to
    // each incremental new state root.
    signal input currentStateLeaves[batchSize][STATE_LEAF_LENGTH];
    signal input currentStateLeavesPathElements[batchSize][stateTreeDepth][TREE_ARITY - 1];

    // The salted commitment to the state root
    signal input currentStateCommitment;
    signal input currentStateSalt;

    // The salted commitment to the new state root
    signal input newStateCommitment;
    signal input newStateSalt;

    signal input currentVoteWeights[batchSize];
    signal input currentVoteWeightsPathElements[batchSize][voteOptionTreeDepth][TREE_ARITY - 1];

    // vote option tree zero root
    component calculateVOTreeZeroRoot = ZeroRoot(voteOptionTreeDepth);
    signal voTreeZeroRoot;
    voTreeZeroRoot <== calculateVOTreeZeroRoot.out;

    // Verify currentStateCommitment
    component currentStateCommitmentHasher = HashLeftRight(); 
    currentStateCommitmentHasher.left <== currentStateRoot;
    currentStateCommitmentHasher.right <== currentStateSalt;
    currentStateCommitmentHasher.hash === currentStateCommitment;

    // Verify "public" inputs and assign unpacked values
    component inputHasher = ProcessMessagesInputHasher();
    inputHasher.packedVals <== packedVals;
    inputHasher.coordPubKey[0] <== coordPubKey[0];
    inputHasher.coordPubKey[1] <== coordPubKey[1];
    inputHasher.batchStartHash <== batchStartHash;
    inputHasher.batchEndHash <== batchEndHash;
    inputHasher.currentStateCommitment <== currentStateCommitment;
    inputHasher.newStateCommitment <== newStateCommitment;

    // The unpacked values from packedVals
    inputHasher.maxVoteOptions ==> maxVoteOptions;
    inputHasher.numSignUps ==> numSignUps;

    inputHasher.hash === inputHash;

    //  ----------------------------------------------------------------------- 
    //      0. Ensure that the maximum vote options signal is valid and whether
    //      the maximum users signal is valid
    component maxVoValid = LessEqThan(32);
    maxVoValid.in[0] <== maxVoteOptions;
    maxVoValid.in[1] <== TREE_ARITY ** voteOptionTreeDepth;
    maxVoValid.out === 1;

    component numSignUpsValid = LessEqThan(32);
    numSignUpsValid.in[0] <== numSignUps;
    numSignUpsValid.in[1] <== TREE_ARITY ** stateTreeDepth;
    numSignUpsValid.out === 1;

    //  ----------------------------------------------------------------------- 
    //  Check whether each message exists in the message hash chain. Throw
    //  if otherwise (aka create a constraint that prevents such a proof).

    component messageHashers[batchSize];
    component isEmptyMsg[batchSize];
    component muxes[batchSize];

    signal msgHashChain[batchSize + 1];
    msgHashChain[0] <== batchStartHash;

    // msgChainHash[m] = isEmptyMessage
    //   ? msgChainHash[m - 1]
    //   : hash( hash(msg[m]) , msgChainHash[m - 1] )

    for (var i = 0; i < batchSize; i ++) {
        messageHashers[i] = MessageHasher();
        for (var j = 0; j < MSG_LENGTH; j ++) {
            messageHashers[i].in[j] <== msgs[i][j];
        }
        messageHashers[i].encPubKey[0] <== encPubKeys[i][0];
        messageHashers[i].encPubKey[1] <== encPubKeys[i][1];
        messageHashers[i].prevHash <== msgHashChain[i];

        isEmptyMsg[i] = IsZero();
        isEmptyMsg[i].in <== encPubKeys[i][0];

        muxes[i] = Mux1();
        muxes[i].s <== isEmptyMsg[i].out;
        muxes[i].c[0] <== messageHashers[i].hash;
        muxes[i].c[1] <== msgHashChain[i];

        msgHashChain[i + 1] <== muxes[i].out;
    }
    msgHashChain[batchSize] === batchEndHash;

    //  ----------------------------------------------------------------------- 
    //  Decrypt each Message to a Command

    // MessageToCommand derives the ECDH shared key from the coordinator's
    // private key and the message's ephemeral public key. Next, it uses this
    // shared key to decrypt a Message to a Command.

    // Ensure that the coordinator's public key from the contract is correct
    // based on the given private key - that is, the prover knows the
    // coordinator's private key.
    component derivedPubKey = PrivToPubKey();
    derivedPubKey.privKey <== coordPrivKey;
    derivedPubKey.pubKey[0] === coordPubKey[0];
    derivedPubKey.pubKey[1] === coordPubKey[1];

    // Decrypt each Message into a Command
    component commands[batchSize];
    for (var i = 0; i < batchSize; i ++) {
        commands[i] = MessageToCommand();
        commands[i].encPrivKey <== coordPrivKey;
        commands[i].encPubKey[0] <== encPubKeys[i][0];
        commands[i].encPubKey[1] <== encPubKeys[i][1];
        for (var j = 0; j < MSG_LENGTH; j ++) {
            commands[i].message[j] <== msgs[i][j];
        }
    }

    signal stateRoots[batchSize + 1];
    // signal ballotRoots[batchSize + 1];

    stateRoots[batchSize] <== currentStateRoot;
    // ballotRoots[batchSize] <== currentBallotRoot;

    //  ----------------------------------------------------------------------- 
    //  Process messages in reverse order
    component processors[batchSize];
    for (var i = batchSize - 1; i >= 0; i --) {
        processors[i] = ProcessOne(stateTreeDepth, voteOptionTreeDepth);

        processors[i].numSignUps <== numSignUps;
        processors[i].maxVoteOptions <== maxVoteOptions;

        processors[i].currentStateRoot <== stateRoots[i + 1];

        processors[i].voTreeZeroRoot <== voTreeZeroRoot;

        for (var j = 0; j < STATE_LEAF_LENGTH; j ++) {
            processors[i].stateLeaf[j] <== currentStateLeaves[i][j];
        }

        for (var j = 0; j < stateTreeDepth; j ++) {
            for (var k = 0; k < TREE_ARITY - 1; k ++) {
                processors[i].stateLeafPathElements[j][k] 
                    <== currentStateLeavesPathElements[i][j][k];
            }
        }

        processors[i].currentVoteWeight <== currentVoteWeights[i];

        for (var j = 0; j < voteOptionTreeDepth; j ++) {
            for (var k = 0; k < TREE_ARITY - 1; k ++) {
                processors[i].currentVoteWeightsPathElements[j][k]
                    <== currentVoteWeightsPathElements[i][j][k];
            }
        }

        processors[i].cmdStateIndex <== commands[i].stateIndex;
        processors[i].cmdNewPubKey[0] <== commands[i].newPubKey[0];
        processors[i].cmdNewPubKey[1] <== commands[i].newPubKey[1];
        processors[i].cmdVoteOptionIndex <== commands[i].voteOptionIndex;
        processors[i].cmdNewVoteWeight <== commands[i].newVoteWeight;
        processors[i].cmdNonce <== commands[i].nonce;
        processors[i].cmdSigR8[0] <== commands[i].sigR8[0];
        processors[i].cmdSigR8[1] <== commands[i].sigR8[1];
        processors[i].cmdSigS <== commands[i].sigS;
        for (var j = 0; j < PACKED_CMD_LENGTH; j ++) {
            processors[i].packedCmd[j] <== commands[i].packedCommandOut[j];
        }

        stateRoots[i] <== processors[i].newStateRoot;
    }

    component stateCommitmentHasher = HashLeftRight();
    stateCommitmentHasher.left <== stateRoots[0];
    stateCommitmentHasher.right <== newStateSalt;

    stateCommitmentHasher.hash === newStateCommitment;
}

template ProcessOne(stateTreeDepth, voteOptionTreeDepth) {
    /*
        transform(currentStateLeaves0, cmd0) -> newStateLeaves0, isValid0
        genIndices(isValid0, cmd0) -> pathIndices0
        verify(currentStateRoot, pathElements0, pathIndices0, currentStateLeaves0)
        qip(newStateLeaves0, pathElements0) -> newStateRoot0
    */
    var MSG_LENGTH = 7;
    var PACKED_CMD_LENGTH = 3;
    var TREE_ARITY = 5;

    // var BALLOT_LENGTH = 2;

    // var BALLOT_NONCE_IDX = 0;
    // var BALLOT_VO_ROOT_IDX = 1;

    var STATE_LEAF_LENGTH = 5;

    var STATE_LEAF_PUB_X_IDX = 0;
    var STATE_LEAF_PUB_Y_IDX = 1;
    var STATE_LEAF_VOICE_CREDIT_BALANCE_IDX = 2;
    var STATE_LEAF_VO_ROOT_IDX = 3;
    var STATE_LEAF_NONCE_IDX = 4;

    signal input numSignUps;
    signal input maxVoteOptions;

    signal input currentStateRoot;

    signal input voTreeZeroRoot;

    signal input stateLeaf[STATE_LEAF_LENGTH];
    signal input stateLeafPathElements[stateTreeDepth][TREE_ARITY - 1];

    signal input currentVoteWeight;
    signal input currentVoteWeightsPathElements[voteOptionTreeDepth][TREE_ARITY - 1];

    signal input cmdStateIndex;
    signal input cmdNewPubKey[2];
    signal input cmdVoteOptionIndex;
    signal input cmdNewVoteWeight;
    signal input cmdNonce;
    signal input cmdSigR8[2];
    signal input cmdSigS;
    signal input packedCmd[PACKED_CMD_LENGTH];

    signal output newStateRoot;

    //  ----------------------------------------------------------------------- 
    // 1. Transform a state leaf with a command.
    // The result is a new state leaf and an isValid signal (0
    // or 1)
    component transformer = StateLeafTransformer();
    transformer.numSignUps                     <== numSignUps;
    transformer.maxVoteOptions                 <== maxVoteOptions;
    transformer.slPubKey[STATE_LEAF_PUB_X_IDX] <== stateLeaf[STATE_LEAF_PUB_X_IDX];
    transformer.slPubKey[STATE_LEAF_PUB_Y_IDX] <== stateLeaf[STATE_LEAF_PUB_Y_IDX];
    transformer.slVoiceCreditBalance           <== stateLeaf[STATE_LEAF_VOICE_CREDIT_BALANCE_IDX];
    transformer.slNonce                        <== stateLeaf[STATE_LEAF_NONCE_IDX];
    transformer.currentVotesForOption          <== currentVoteWeight;
    transformer.cmdStateIndex                  <== cmdStateIndex;
    transformer.cmdNewPubKey[0]                <== cmdNewPubKey[0];
    transformer.cmdNewPubKey[1]                <== cmdNewPubKey[1];
    transformer.cmdVoteOptionIndex             <== cmdVoteOptionIndex;
    transformer.cmdNewVoteWeight               <== cmdNewVoteWeight;
    transformer.cmdNonce                       <== cmdNonce;
    transformer.cmdSigR8[0]                    <== cmdSigR8[0];
    transformer.cmdSigR8[1]                    <== cmdSigR8[1];
    transformer.cmdSigS                        <== cmdSigS;
    for (var i = 0; i < PACKED_CMD_LENGTH; i ++) {
        transformer.packedCommand[i]           <== packedCmd[i];
    }

    //  ----------------------------------------------------------------------- 
    // 2. If isValid is 0, generate indices for leaf 0
    //    Otherwise, generate indices for commmand.stateIndex
    component stateIndexMux = Mux1();
    stateIndexMux.s <== transformer.isValid;
    stateIndexMux.c[0] <== 0;
    stateIndexMux.c[1] <== cmdStateIndex;

    component stateLeafPathIndices = QuinGeneratePathIndices(stateTreeDepth);
    stateLeafPathIndices.in <== stateIndexMux.out;

    //  ----------------------------------------------------------------------- 
    // 3. Verify that the original state leaf exists in the given state root
    component stateLeafQip = QuinTreeInclusionProof(stateTreeDepth);
    component stateLeafHasher = Hasher5();
    for (var i = 0; i < STATE_LEAF_LENGTH; i++) {
        stateLeafHasher.in[i] <== stateLeaf[i];
    }
    stateLeafQip.leaf <== stateLeafHasher.hash;
    for (var i = 0; i < stateTreeDepth; i ++) {
        stateLeafQip.path_index[i] <== stateLeafPathIndices.out[i];
        for (var j = 0; j < TREE_ARITY - 1; j++) {
            stateLeafQip.path_elements[i][j] <== stateLeafPathElements[i][j];
        }
    }
    stateLeafQip.root === currentStateRoot;

    //  ----------------------------------------------------------------------- 
    // 5. Verify that currentVoteWeight exists in the ballot's vote option root
    // at cmdVoteOptionIndex

    component cmdVoteOptionIndexMux = Mux1();
    cmdVoteOptionIndexMux.s <== transformer.isValid;
    cmdVoteOptionIndexMux.c[0] <== 0;
    cmdVoteOptionIndexMux.c[1] <== cmdVoteOptionIndex;

    component currentVoteWeightPathIndices = QuinGeneratePathIndices(voteOptionTreeDepth);
    currentVoteWeightPathIndices.in <== cmdVoteOptionIndexMux.out;

    component currentVoteWeightQip = QuinTreeInclusionProof(voteOptionTreeDepth);
    currentVoteWeightQip.leaf <== currentVoteWeight;
    for (var i = 0; i < voteOptionTreeDepth; i ++) {
        currentVoteWeightQip.path_index[i] <== currentVoteWeightPathIndices.out[i];
        for (var j = 0; j < TREE_ARITY - 1; j++) {
            currentVoteWeightQip.path_elements[i][j] <== currentVoteWeightsPathElements[i][j];
        }
    }

    component slvoRootIsZero = IsZero();
    slvoRootIsZero.in <== stateLeaf[STATE_LEAF_VO_ROOT_IDX];
    component voRootMux = Mux1();
    voRootMux.s <== slvoRootIsZero.out;
    voRootMux.c[0] <== stateLeaf[STATE_LEAF_VO_ROOT_IDX];
    voRootMux.c[1] <== voTreeZeroRoot;
    currentVoteWeightQip.root === voRootMux.out;

    component voteWeightMux = Mux1();
    voteWeightMux.s <== transformer.isValid;
    voteWeightMux.c[0] <== currentVoteWeight;
    voteWeightMux.c[1] <== cmdNewVoteWeight;

    //  ----------------------------------------------------------------------- 
    // 5.1. Update vote option root with the new vote weight
    component newVoteOptionTreeQip = QuinTreeInclusionProof(voteOptionTreeDepth);
    newVoteOptionTreeQip.leaf <== voteWeightMux.out;
    for (var i = 0; i < voteOptionTreeDepth; i ++) {
        newVoteOptionTreeQip.path_index[i] <== currentVoteWeightPathIndices.out[i];
        for (var j = 0; j < TREE_ARITY - 1; j++) {
            newVoteOptionTreeQip.path_elements[i][j] <== currentVoteWeightsPathElements[i][j];
        }
    }

    //  ----------------------------------------------------------------------- 
    // 6. Generate a new state root

    signal newBalance;
    newBalance <== stateLeaf[STATE_LEAF_VOICE_CREDIT_BALANCE_IDX] + currentVoteWeight - cmdNewVoteWeight;

    // The new balance
    component voiceCreditBalanceMux = Mux1();
    voiceCreditBalanceMux.s <== transformer.isValid;
    voiceCreditBalanceMux.c[0] <== stateLeaf[STATE_LEAF_VOICE_CREDIT_BALANCE_IDX];
    voiceCreditBalanceMux.c[1] <== newBalance;

    // The new vote option root
    component newVoteOptionRootMux = Mux1();
    newVoteOptionRootMux.s <== transformer.isValid;
    newVoteOptionRootMux.c[0] <== stateLeaf[STATE_LEAF_VO_ROOT_IDX];
    newVoteOptionRootMux.c[1] <== newVoteOptionTreeQip.root;

    // The new nonce
    component newSlNonceMux = Mux1();
    newSlNonceMux.s <== transformer.isValid;
    newSlNonceMux.c[0] <== stateLeaf[STATE_LEAF_NONCE_IDX];
    newSlNonceMux.c[1] <== transformer.newSlNonce;

    component newStateLeafHasher = Hasher5();
    newStateLeafHasher.in[STATE_LEAF_PUB_X_IDX] <== transformer.newSlPubKey[STATE_LEAF_PUB_X_IDX];
    newStateLeafHasher.in[STATE_LEAF_PUB_Y_IDX] <== transformer.newSlPubKey[STATE_LEAF_PUB_Y_IDX];
    newStateLeafHasher.in[STATE_LEAF_VOICE_CREDIT_BALANCE_IDX] <== voiceCreditBalanceMux.out;
    newStateLeafHasher.in[STATE_LEAF_VO_ROOT_IDX] <== newVoteOptionRootMux.out;
    newStateLeafHasher.in[STATE_LEAF_NONCE_IDX] <== newSlNonceMux.out;

    component newStateLeafQip = QuinTreeInclusionProof(stateTreeDepth);
    newStateLeafQip.leaf <== newStateLeafHasher.hash;
    for (var i = 0; i < stateTreeDepth; i ++) {
        newStateLeafQip.path_index[i] <== stateLeafPathIndices.out[i];
        for (var j = 0; j < TREE_ARITY - 1; j++) {
            newStateLeafQip.path_elements[i][j] <== stateLeafPathElements[i][j];
        }
    }
    newStateRoot <== newStateLeafQip.root;
}

template ProcessMessagesInputHasher() {
    // Combine the following into 1 input element:
    // - maxVoteOptions (32 bits)
    // - numSignUps (32 bits)

    // Hash coordPubKey:
    // - coordPubKeyHash 

    // Other inputs that can't be compressed or packed:
    // - batchStartHash, batchEndHash, currentStateCommitment,
    //   newStateCommitment

    // Also ensure that packedVals is valid

    signal input packedVals;
    signal input coordPubKey[2];
    signal input batchStartHash;
    signal input batchEndHash;
    signal input currentStateCommitment;
    signal input newStateCommitment;

    signal output maxVoteOptions;
    signal output numSignUps;
    signal output hash;
    
    // 1. Unpack packedVals and ensure that it is valid
    component unpack = UnpackElement(2);
    unpack.in <== packedVals;

    maxVoteOptions <== unpack.out[1];
    numSignUps <== unpack.out[0];

    // 2. Hash coordPubKey
    component pubKeyHasher = HashLeftRight();
    pubKeyHasher.left <== coordPubKey[0];
    pubKeyHasher.right <== coordPubKey[1];

    // 3. Hash the 6 inputs with SHA256
    component hasher = Sha256Hasher6();
    hasher.in[0] <== packedVals;
    hasher.in[1] <== pubKeyHasher.hash;
    hasher.in[2] <== batchStartHash;
    hasher.in[3] <== batchEndHash;
    hasher.in[4] <== currentStateCommitment;
    hasher.in[5] <== newStateCommitment;

    hash <== hasher.hash;
}
