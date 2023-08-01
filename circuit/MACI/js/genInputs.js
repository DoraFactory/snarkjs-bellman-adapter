const fs = require('fs')
const path = require('path')
const { stringizing, genRandomKey } = require('./keypair')
const MACI = require('./maci')


function toBigInt(list) {
  return list.map(n => BigInt(n))
}

const coordinatorKey = BigInt(process.argv[2])

const logsPath = path.join(__dirname, '../build/contract-logs.json')
const outputPath = path.join(__dirname, '../build/inputs')

const rawdata = fs.readFileSync(logsPath)
const logs = JSON.parse(rawdata)

// * DEV *
const maxVoteOptions = 30
const main = new MACI(
  7, 3, 3, 125,               // tree config
  coordinatorKey,
  maxVoteOptions,
  logs.states.length,
)

for (const state of logs.states) {
  main.initStateTree(Number(state.idx), toBigInt(state.pubkey), state.balance)
}

for (const msg of logs.messages) {
  main.pushMessage(toBigInt(msg.msg), toBigInt(msg.pubkey))
}

main.endVotePeriod()

const commitments = {}

// PROCESSING
let i = 0
while (main.states === 1) {
  const input = main.processMessage(genRandomKey())
  commitments['msg_' + i.toString().padStart(4, '0')] = main.stateCommitment

  fs.writeFileSync(
    path.join(outputPath, `msg-input_${i.toString().padStart(4, '0')}.json`),
    JSON.stringify(stringizing(input), undefined, 2)
  )
  i++
}

// TALLYING
i = 0
while (main.states === 2) {
  const input = main.processTally(genRandomKey())
  commitments['tally_' + i.toString().padStart(4, '0')] = main.tallyCommitment

  fs.writeFileSync(
    path.join(outputPath, `tally-input_${i.toString().padStart(4, '0')}.json`),
    JSON.stringify(stringizing(input), undefined, 2)
  )
  i++
}

fs.writeFileSync(
  path.join(outputPath, 'result.json'),
  JSON.stringify(stringizing(main.tallyResults.leaves().slice(0, maxVoteOptions)), undefined, 2)
)

fs.writeFileSync(
  path.join(outputPath, 'commitments.json'),
  JSON.stringify(stringizing(commitments), undefined, 2)
)
