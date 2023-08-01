const fs = require('fs')
const path = require('path')
const { stringizing, genKeypair } = require('./keypair')
const MACI = require('./maci')
const { genMessage } = require('./client')

const outputPath = process.argv[2]
if (!outputPath) {
  console.log('no output directory is specified')
  process.exit(1)
}

const USER_1 = 0        // state leaf idx
const USER_2 = 1        // state leaf idx

const privateKeys = [
  111111n, // coordinator
  222222n, // user 1
  333333n, // share key for message 1
  444444n, // share key for message 2
  555555n, // user 2
  666666n, // share key for message 3
]
const coordinator = genKeypair(privateKeys[0])
const user1 = genKeypair(privateKeys[1])
const user2 = genKeypair(privateKeys[4])

const main = new MACI(
  2, 1, 1, 5,               // tree config
  privateKeys[0],         // coordinator
  5,
  2
)

main.initStateTree(USER_1, user1.pubKey, 100)
main.initStateTree(USER_2, user2.pubKey, 80)

const enc1 = genKeypair(privateKeys[2])
const message1 = genMessage(enc1.privKey, coordinator.pubKey)(
  USER_1, 2, 12, 8, user1.pubKey, user1.privKey, 1234567890n
)
main.pushMessage(message1, enc1.pubKey)

const enc3 = genKeypair(privateKeys[5])
const message3 = genMessage(enc3.privKey, coordinator.pubKey)(
  USER_2, 1, 8, 5, user2.pubKey, user2.privKey, 1234567890n
)
main.pushMessage(message3, enc3.pubKey)

const enc2 = genKeypair(privateKeys[3])
const message2 = genMessage(enc2.privKey, coordinator.pubKey)(
  USER_1, 1, 8, 6, user1.pubKey, user1.privKey, 9876543210n
)
main.pushMessage(message2, enc2.pubKey)

main.endVotePeriod()

// PROCESSING
let i = 0
while (main.states === 1) {
  const input = main.processMessage(1234567890n)

  fs.writeFileSync(
    path.join(outputPath, `msg-input_${i.toString().padStart(4, '0')}.json`),
    JSON.stringify(stringizing(input), undefined, 2)
  )
  i++
}

// TALLYING
i = 0
while (main.states === 2) {
  const input = main.processTally(1234567890n)

  fs.writeFileSync(
    path.join(outputPath, `tally-input_${i.toString().padStart(4, '0')}.json`),
    JSON.stringify(stringizing(input), undefined, 2)
  )
  i++
}

fs.writeFileSync(
  path.join(outputPath, 'logs.json'),
  JSON.stringify(main.logs, undefined, 2)
)
