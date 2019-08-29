const fs = require('fs')
const kg = require('../src/index')

const write = (wal, num) => {
  fs.writeFile(
    `${__dirname}/assets/wallet${num}.json`,
    JSON.stringify(wal, null, ' '),
    _ => console.log('written')
  )
}

const main = async () => {
  let config = {
    ticket: '~doznec-marbud',
    ship: 1
  }
  let wallet = await kg.generateWallet(config)

  write(wallet, 0)

  config = {
    ticket: '~marbud-tidsev-litsut-hidfep',
    ship: 65012,
    boot: true
  }
  wallet = await kg.generateWallet(config)

  write(wallet, 1)

  config = {
    ticket: '~wacfus-dabpex-danted-mosfep-pasrud-lavmer-nodtex-taslus-pactyp-milpub-pildeg-fornev-ralmed-dinfeb-fopbyr-sanbet-sovmyl-dozsut-mogsyx-mapwyc-sorrup-ricnec-marnys-lignex',
    passphrase: 'froot loops',
    ship: 222,
    revision: 6
  }
  wallet = await kg.generateWallet(config)

  write(wallet, 2)

  config = {
    ticket: '~doznec-marbud',
    ship: 0
  }
  wallet = await kg.generateWallet(config)

  write(wallet, 3)

  config = {
    ticket: '~doznec-marbud',
    ship: 0x00ffffff
  }
  wallet = await kg.generateWallet(config)

  write(wallet, 4)
}

main()
