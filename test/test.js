const bip32 = require('bip32')
const bip39 = require('bip39')
const { expect } = require('chai')
const fs = require('fs-extra')
const jsc = require('jsverify')
const lodash = require('lodash')
const ob = require('urbit-ob')
const util = require('ethereumjs-util')
const crypto = require('isomorphic-webcrypto')

const kg = require('../src')

const objectFromFile = (path) => {
  const fd = fs.openSync(path, 'r')
  const contents = fs.readFileSync(fd)
  fs.closeSync(fd)
  const text = contents.toString()
  return JSON.parse(text)
}

const replicate = (n, g) => jsc.tuple(new Array(n).fill(g))

const buffer256 = replicate(32, jsc.uint8).smap(
  arr => Buffer.from(arr),
  buf => Array.from(buf)
)

const buffer384 = replicate(48, jsc.uint8).smap(
  arr => Buffer.from(arr),
  buf => Array.from(buf)
)

const mnemonic = replicate(16, jsc.uint8).smap(
  bip39.entropyToMnemonic,
  bip39.mnemonicToEntropy
)

// tests

describe('toChecksumAddress', () => {
  it('matches a reference implementation', () => {
    let prop = jsc.forall(buffer256, buf => {
      let hashed = kg._keccak256(buf.toString('hex'))
      let addr = kg._addHexPrefix(hashed.slice(-20).toString('hex'))
      return util.toChecksumAddress(addr) === kg._toChecksumAddress(addr)
    })

    jsc.assert(prop)
  })
})

describe('hex prefix utils', () => {
  it('work as expected', () => {
    expect(kg._addHexPrefix('0102')).to.equal('0x0102')
    expect(kg._addHexPrefix('0x0102')).to.equal('0x0102')
    expect(kg._stripHexPrefix('0x0102')).to.equal('0102')
    expect(kg._stripHexPrefix('0102')).to.equal('0102')
  })
})

describe('isGalaxy', () => {
  const galaxies = jsc.integer(0, 255)
  const nongalaxies = jsc.integer(256, 4294967295)

  it('identifies galaxies correctly', () => {
    let prop = jsc.forall(galaxies, kg._isGalaxy)
    jsc.assert(prop)
  })

  it('identifies non-galaxies correctly', () => {
    let prop = jsc.forall(nongalaxies, ship => kg._isGalaxy(ship) === false)
    jsc.assert(prop)
  })
})

describe('shard and combine', () => {
  it('does not shard non-384-bit tickets', () => {
    let ticket = '~doznec-marbud'
    expect(kg.shard(ticket)).to.have.lengthOf(1)
  })

  it('shards 384-bit tickets', () => {
    let ticket = '~wacfus-dabpex-danted-mosfep-pasrud-lavmer-nodtex-taslus-pactyp-milpub-pildeg-fornev-ralmed-dinfeb-fopbyr-sanbet-sovmyl-dozsut-mogsyx-mapwyc-sorrup-ricnec-marnys-lignex'
    expect(kg.shard(ticket)).to.have.lengthOf(3)
  })

  it('produces valid shards', () => {
    let prop = jsc.forall(buffer384, buf => {
      let ticket = ob.hex2patq(buf.toString('hex'))
      let shards = kg.shard(ticket)

      return (
        kg.combine([shards[0], shards[1], undefined]) === ticket &&
        kg.combine([shards[0], undefined, shards[2]]) === ticket &&
        kg.combine([undefined, shards[1], shards[2]]) === ticket
      )
    })

    jsc.assert(prop)
  })

  it('throws when insufficient shards', () => {
    expect(() => kg.combine([undefined, undefined, undefined])).to.throw()
  })
})

describe('argon2u', () => {
  it('produces 32 bytelength hashes', async function() {
    this.timeout(10000)

    let res = await kg.argon2u('my rad entropy', 0)

    expect(res).to.not.be.undefined
    expect(res).to.have.lengthOf(32)
  })

  it('uses the ship number as a salt', async function() {
    this.timeout(10000)

    let res0 = await kg.argon2u('my rad entropy', 0)
    let res1 = await kg.argon2u('my rad entropy', 1)

    expect(res0).to.not.equal(res1)
  })
})

describe('sha256', () => {
  const sha256 = (...args) => {
    const buffer = Buffer.concat(args.map(x => Buffer.from(x)))
    return crypto.subtle.digest({ name: 'SHA-256' }, buffer)
  }

  it('produces 256-bit digests', () => {
    let prop = jsc.forall(jsc.string, str => {
      let digest = kg._sha256(str)
      return digest.byteLength === 32
    })
    jsc.assert(prop)
  })

  it('works as expected', () => {
    let helloHash =
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

    let hash = kg._sha256('hello')
    let hashHex = Buffer.from(hash).toString('hex')

    expect(hashHex).to.equal(helloHash)
  })

  it('matches our old isomorphic-webcrypto-based implementation', () => {
    let prop = jsc.forall(jsc.string, async str => {
      let hash0 = kg._sha256(str)
      let hash1 = await sha256(str)
      let hex0 = Buffer.from(hash0).toString('hex')
      let hex1 = Buffer.from(hash1).toString('hex')
      return hex0 === hex1
    })
    jsc.assert(prop)
  })
})


describe('deriveNodeSeed', () => {
  let types = Object.values(kg.CHILD_SEED_TYPES)
  let nonNetworkSeedType = jsc.oneof(
    types
      .filter(type => type !== kg.CHILD_SEED_TYPES.NETWORK)
      .map(jsc.constant)
  )

  let config = jsc.record({
    seed: buffer256,
    type: nonNetworkSeedType,
  })

  it('produces valid BIP39 mnemonics for non-network seeds', () => {
    let prop = jsc.forall(config, cfg => {
      let { seed, type } = cfg
      let child = kg.deriveNodeSeed(seed, type)
      return bip39.validateMnemonic(child)
    })
    jsc.assert(prop)
  })

  it('uses the seed type to salt the master seed', () => {
    let prop = jsc.forall(config, cfg0 => {
      let { seed, type } = cfg0

      let seed0 = kg.deriveNodeSeed(seed, type)
      let seed1 = kg.deriveNodeSeed(seed, 'bollocks')

      return lodash.isEqual(seed0, seed1) === false
    })

    jsc.assert(prop)
  })

  it('works as expected', () => {
    let seed = Buffer.from('b2bdf8de8452b18f02195b6e7bfc82b900fbcc25681f07ae10f38f11e5af53af', 'hex')

    let child = kg.deriveNodeSeed(seed, 'management')
    let mnem = 'bonus favorite swallow panther frequent random essence loop motion apology skull ginger subject exchange please series meadow tree latin smile bring process excite tornado'

    expect(child).to.equal(mnem)

    child = kg.deriveNodeSeed(seed, 'ownership')
    mnem = 'impact keep magnet two rice country girl jungle cabin mystery usual tree horn skull winter palace supreme reform sphere cabbage cry athlete puppy misery'

    expect(child).to.equal(mnem)
  })

})

describe('deriveNodeKeys', () => {

  const VALID_PATH = "m/44'/60'/0'/0/0"
  const INVALID_PATH = "m/44'/60/0'/0/0"

  it('derives by paths correctly', () => {
    let prop = jsc.forall(mnemonic, mnem => {
      let seed = bip39.mnemonicToSeed(mnem)
      let hd = bip32.fromSeed(seed)
      let wallet0 = hd.derivePath(VALID_PATH)
      let wallet1 = hd.derivePath(INVALID_PATH)

      let keys0 = {
        public: wallet0.publicKey.toString('hex'),
        private: wallet0.privateKey.toString('hex'),
        chain: wallet0.chainCode.toString('hex'),
        address: kg.addressFromSecp256k1Public(wallet0.publicKey.toString('hex'))
      }

      let keys1 = {
        public: wallet1.publicKey.toString('hex'),
        private: wallet1.privateKey.toString('hex'),
        chain: wallet1.chainCode.toString('hex'),
        address: kg.addressFromSecp256k1Public(wallet1.publicKey.toString('hex'))
      }

      let node = kg.deriveNodeKeys(mnem)

      return keys0.public === node.public
        && keys0.private === node.private
        && keys0.chain === node.chain
        && keys0.address === node.address
        && keys1.public !== node.public
        && keys1.private !== node.private
        && keys1.chain !== node.chain
        && keys1.address !== node.address
    })

    jsc.assert(prop)
  })

  it('has the correct properties', () => {
    let prop = jsc.forall(mnemonic, mnem => {
      let node = kg.deriveNodeKeys(mnem)

      return 'public' in node && 'private' in node && 'chain' in node &&
        'address' in node
    })
  })

  it('works as expected', () => {
    let node = kg.deriveNodeKeys(
      'market truck nice joke upper divide spot essay mosquito mushroom buzz undo'
    )

    let expected = {
      public:
        '0208489b1c97859b10106f2019d8fe0c64fc6c3439fdbe99a81c016cfe33e902bc',
      private:
        'fc4475d16c797542d3e6c0907a6bdff81aed9c1efa8e5c2b82bc72d36e8de1b2',
      chain:
        '51ede5795e85de1f6b4032b152704f1fca125402f9fe1835fc2a82863f617125',
      address:
        '0xB8517352a8F1DDe913b191CCDB0D2124e95983a3'
    }

    expect(lodash.isEqual(node, expected)).to.equal(true)
  })

})


describe('deriveNetworkKeys', () => {
  it('matches ++pit:nu:crub:crypto', () => {
    // to compare w/keygen-hoon:
    //
    // ~zod:dojo> /+ keygen
    // ~zod:dojo> (urbit:sd:keygen (to-byts:keygen 'my-input'))

    let expected = {
      crypt:
       { private:
          '9c513a22795147661234eea13ee5fa5b1a8b9bed1aa4b1cf87f6bcf353afa8bb',
         public:
          'f7187602dff5e3eea27b4c46368601106916d704a2ef2e451838d4ea80b395e0' },
      auth:
       { private:
          '52c830cd009a4c6599778b258fa8898cb8b49dd71279c7ca502cb04c2f530d7a',
         public:
          '9a09b7e816467b10ebdcd47d71861a2d0896189f2e66690b636ad3bdf8fcc343' }
    }

    let seed = Buffer.from('88359ba61d766e1c2ec9598831668d4233b0f8f58b29da8cf33d25b2590d62a0', 'hex')
    let keys = kg.deriveNetworkKeys(seed)

    expect(lodash.isEqual(keys, expected)).to.equal(true)

    seed = Buffer.from('52dc7422d68c0209610502e71009d6e9f054da2accafb612180c853f3f77d606', 'hex');
    keys = kg.deriveNetworkKeys(seed)

    expected = {
      crypt:
       { private:
          '972bd3bc056ac414a3c38bc948a74506120b2fc84ae22ba605c9eeef2b7cc1db',
         public:
          'fadea0a37e6d111eb0806648fa66d689f200f38cfd1e3fe683fc148d76c69d27' },
      auth:
       { private:
          '25619a9ce9458f869f064ca5693785283a20aa7a8433baf5fcccbb0a84f76cae',
         public:
          '76fa3a858dfeb18fd7cd1a63b2fe84f95840e3e5b19e0e6950692cbdc55f3821' }
    }

    expect(lodash.isEqual(keys, expected)).to.equal(true)
  })

  it('contains the expected fields', () => {
    let prop = jsc.forall(jsc.string, str => {
      let keys = kg.deriveNetworkKeys(Buffer.from(str))

      return 'auth' in keys && 'crypt' in keys
        && 'public' in keys.auth && 'private' in keys.auth
        && 'public' in keys.crypt && 'private' in keys.crypt
    })

    jsc.assert(prop, { tests: 50 })
  })
})

describe('ethereum addresses from keys', () => {
  it('derives correct addresses', () => {
    const checkAddress = config  => {
      let { epriv, epub, eaddr } = config
      let fromPub = kg.addressFromSecp256k1Public(epub)

      expect(fromPub === eaddr).to.equal(true)
    }

    let config = {
      epriv: '0000000000000000000000000000000000000000000000000000000000000001',
      epub: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      eaddr: '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf'
    }

    checkAddress(config)

    config = {
      epriv: 'b205a1e03ddf50247d8483435cd91f9c732bad281ad420061ab4310c33166276',
      epub: '036cb84859e85b1d9a27e060fdede38bb818c93850fb6e42d9c7e4bd879f8b9153',
      eaddr: '0xAFdEfC1937AE294C3Bd55386A8b9775539d81653'
    }

    checkAddress(config)

    config = {
      epriv: '44b9abf2708d9adeb1722dcc1e61bef14e5611dee710d66f106e356a111bef90',
      epub: '02cabb8a3a73ea4a03d025a6ac2ebbbb19a545e4fb10e791ec9b5c942d77aa2076',
      eaddr: '0xa0784ba3fcea41fD65a7A47b4cc1FA4C3DaA326f'
    }

    checkAddress(config)

    config = {
      epriv: '208065a247edbe5df4d86fbdc0171303f23a76961be9f6013850dd2bdc759bbb',
      epub: '02836b35a026743e823a90a0ee3b91bf615c6a757e2b60b9e1dc1826fd0dd16106',
      eaddr: '0x0BED7ABd61247635c1973eB38474A2516eD1D884'
    }

    checkAddress(config)
  })

})

describe('deriveNetworkSeed', () => {
  let single = (mnem, rev) => {
    let seed = bip39.mnemonicToSeed(mnem)
    let hash = kg._sha256(seed, kg.CHILD_SEED_TYPES.NETWORK, `${rev}`)
    return Buffer.from(hash).toString('hex')
  }

  let mnem = 'pitch purpose street child humor ability ginger twenty evoke art loyal duck'

  it('uses SHA-256 on a zero revision number', function() {
    let sin = single(mnem, 0)
    let dub = kg.deriveNetworkSeed(mnem, '', 0)
    expect(sin).to.equal(dub)
  })

  it('uses SHA-256d on nonzero revision numbers', function() {
    let sin = single(mnem, 1)
    let dub = kg.deriveNetworkSeed(mnem, '', 1)
    expect(sin).to.not.equal(dub)
  })

  it('gives different output for nonzero revisions', function() {
    let one = kg.deriveNetworkSeed(mnem, '', 1)
    let two = kg.deriveNetworkSeed(mnem, '', 2)
    expect(one).to.not.equal(two)
  })


})

describe('generateWallet', () => {
  it('generates wallets as expected', async function() {
    this.timeout(20000)

    let config = {
      ticket: '~doznec-marbud',
      ship: 1
    }
    let wallet = await kg.generateWallet(config)
    let expected = objectFromFile('./test/assets/wallet0.json')

    expect(lodash.isEqual(wallet, expected)).to.equal(true)

    config = {
      ticket: '~marbud-tidsev-litsut-hidfep',
      ship: 65012,
      boot: true
    }
    wallet = await kg.generateWallet(config)
    expected = objectFromFile('./test/assets/wallet1.json')

    expect(lodash.isEqual(wallet, expected)).to.equal(true)

    config = {
      ticket: '~wacfus-dabpex-danted-mosfep-pasrud-lavmer-nodtex-taslus-pactyp-milpub-pildeg-fornev-ralmed-dinfeb-fopbyr-sanbet-sovmyl-dozsut-mogsyx-mapwyc-sorrup-ricnec-marnys-lignex',
      passphrase: 'froot loops',
      ship: 222,
      revision: 6
    }
    wallet = await kg.generateWallet(config)
    expected = objectFromFile('./test/assets/wallet2.json')

    expect(lodash.isEqual(wallet, expected)).to.equal(true)

    config = {
      ticket: '~doznec-marbud',
      ship: 0
    }
    wallet = await kg.generateWallet(config)
    expected = objectFromFile('./test/assets/wallet3.json')

    expect(lodash.isEqual(wallet, expected)).to.equal(true)

  })
})

