const { eddsa, poseidon, poseidonEncrypt } = require('circom')
const { bigInt2Buffer, genEcdhSharedKey } = require('./keypair')

const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n

const genMessage = (
  encPriKey, coordPubKey
) => (
  stateIdx, nonce, voIdx, newVotes, newPubKey, signPriKey, salt
) => {
  if (!salt) {
    // uint60
    salt = BigInt(Math.random() * 1073741824).toString() + (Math.random() * 1073741824).toString()
  }

  const packaged =
    BigInt(nonce) +
    (BigInt(stateIdx) << 32n) +
    (BigInt(voIdx) << 64n) +
    (BigInt(newVotes) << 96n) +
    (BigInt(salt) << 192n)
  
  const hash = poseidon([packaged, ...newPubKey])
  const signature = eddsa.signPoseidon(bigInt2Buffer(signPriKey), hash)

  const command = [
    packaged,
    ...newPubKey,
    ...signature.R8,
    signature.S,
  ]

  const message = poseidonEncrypt(command, genEcdhSharedKey(encPriKey, coordPubKey), 0n)

  return message
}

module.exports = {
  genMessage
}
