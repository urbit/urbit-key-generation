const fs = require('fs');
const kg = require('../dist/index')


const OUTPUT_PATH = __dirname + '/' + 'bin'

const config = {
  ticket: '~marbud-tidsev-litsut-hidfep',
  ship: 65012,
  boot: true
}

const wallet = kg.generateWallet(config).then(data => {
  fs.writeFileSync(
    `${OUTPUT_PATH}/wallet.json`,
    JSON.stringify(data, null, ' ')
  );
})
