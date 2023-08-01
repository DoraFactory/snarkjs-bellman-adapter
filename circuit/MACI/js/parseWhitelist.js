const fs = require('fs')
const { parse } = require('csv/sync')

const inputFile = process.argv[2]
if (!inputFile) {
  console.log('no input proof is specified')
  process.exit(1)
}

const input = fs.readFileSync(inputFile)
const rawRecords = parse(input)

const addrs = []
const vc = []
for (const item of rawRecords) {
  addrs.push(item[0])
  vc.push(parseInt(item[1]))
}

for (let i = 0; i < addrs.length; i += 1000) {
  fs.writeFileSync(
    `./temp/output_${i}.txt`,
    JSON.stringify(addrs.slice(i, i + 1000)) + ',' + JSON.stringify(vc.slice(i, i + 1000))
  )
}