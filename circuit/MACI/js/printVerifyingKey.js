const fs = require('fs')

const inputFile = process.argv[2]
if (!inputFile) {
  console.log('no input verification_key is specified')
  process.exit(1)
}

if (!/\.json$/.test(inputFile)) {
  console.log('invalid verification_key format, expected *.json')
  process.exit(1)
}

try {
  const rawdata = fs.readFileSync(inputFile)
  const data = JSON.parse(rawdata)

  const output = []

  // alpha1
  output.push(data.vk_alpha_1.slice(0, 2))

  // beta2
  output.push(data.vk_beta_2.slice(0, 2).map(a => a.reverse()))

  // gamma2
  output.push(data.vk_gamma_2.slice(0, 2).map(a => a.reverse()))

  // delta2
  output.push(data.vk_delta_2.slice(0, 2).map(a => a.reverse()))

  // ic
  output.push(data.IC.map(point => point.slice(0, 2)))

  console.log(JSON.stringify(output))
} catch (e) {
  console.log(e.message || e)
  process.exit(1)
}
