const fs = require('fs')

const inputFile = process.argv[2]
if (!inputFile) {
  console.log('no input proof is specified')
  process.exit(1)
}

if (!/\.json$/.test(inputFile)) {
  console.log('invalid proof format, expected *.json')
  process.exit(1)
}

try {
  const rawdata = fs.readFileSync(inputFile)
  const data = JSON.parse(rawdata)

  const output = []

  output.push(...data.pi_a.slice(0, 2))

  output.push(...data.pi_b[0].reverse())
  output.push(...data.pi_b[1].reverse())

  output.push(...data.pi_c.slice(0, 2))

  console.log(JSON.stringify(output))
} catch (e) {
  console.log(e.message || e)
  process.exit(1)
}
