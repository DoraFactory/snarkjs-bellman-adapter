pragma circom 2.0.0;

include "../processMessages.circom";

// state_tree_depth,
// vote_options_tree_depth,
// batch_size

component main {
  public [
    inputHash
  ]
} = ProcessMessages(2, 1, 5);
