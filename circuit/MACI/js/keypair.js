const { babyJub, eddsa, poseidonEncrypt, poseidonDecrypt } = require('circom')
const crypto = require('crypto')
const ff = require('ffjavascript')
const createBlakeHash = require('blake-hash')

const SNARK_FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

const stringizing = (o, path = []) => {
  if (path.includes(o)) {
    throw new Error('loop nesting!')
  }
  const newPath = [...path, o]

  if (Array.isArray(o)) {
    return o.map(item => stringizing(item, newPath))
  } else if (typeof o === 'object') {
    const output = {}
    for (const key in o) {
      output[key] = stringizing(o[key], newPath)
    }
    return output
  } else {
    return o.toString()
  }
}

const bigInt2Buffer = (i) => {
  return Buffer.from(i.toString(16), 'hex')
}

const genRandomKey = () => {
  // Prevent modulo bias
  //const lim = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000')
  //const min = (lim - SNARK_FIELD_SIZE) % SNARK_FIELD_SIZE
  const min = 6350874878119819312338956282401532410528162663560392320966563075034087161851n

  let rand
  while (true) {
    rand = BigInt('0x' + crypto.randomBytes(32).toString('hex'))

    if (rand >= min) {
      break
    }
  }

  const privKey = rand % SNARK_FIELD_SIZE
  return privKey
}

const genPubKey = (privKey) => {
  // Check whether privKey is a field element
  privKey = BigInt(privKey.toString())
  return eddsa.prv2pub(bigInt2Buffer(privKey))
}

const genKeypair = (pkey) => {
  const privKey = pkey || genRandomKey()
  const pubKey = genPubKey(privKey)
  const formatedPrivKey = formatPrivKeyForBabyJub(privKey)

  return { privKey, pubKey, formatedPrivKey }
}

const formatPrivKeyForBabyJub = (privKey) => {
  const sBuff = eddsa.pruneBuffer(
    createBlakeHash("blake512").update(
      bigInt2Buffer(privKey),
    ).digest().slice(0,32)
  )
  const s = ff.utils.leBuff2int(sBuff)
  return ff.Scalar.shr(s, 3)
}

const genEcdhSharedKey = (privKey, pubKey) => {
  const sharedKey = babyJub.mulPointEscalar(pubKey, formatPrivKeyForBabyJub(privKey))
  if (sharedKey[0] === 0n) {
    return [0n, 1n]
  } else {
    return sharedKey
  }
}


module.exports = {
  stringizing,
  bigInt2Buffer,
  genRandomKey,
  genKeypair,
  genEcdhSharedKey
}

// const bob = genKeypair(111111n)
// console.log(bob)
// const alice = genKeypair(20581290025117397817181261615160328137557667676132503327155870263692975425406n)
// console.log(alice)

// const ciphertext = poseidonEncrypt([123456n, 123456n], genEcdhSharedKey(bob.privKey, alice.pubKey), 0n)
// console.log(ciphertext)

// const plaintext = poseidonDecrypt(ciphertext, genEcdhSharedKey(alice.privKey, bob.pubKey), 0n, 2)
// console.log(plaintext)
