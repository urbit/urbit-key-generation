const bip39 = require('bip39')
const { expect } = require('chai')
const fs = require('fs-extra')
const hdkey = require('hdkey')
const jsc = require('jsverify')
const lodash = require('lodash')
const ob = require('urbit-ob')

const kg = require('../src')

const objectFromFile = (path) => {
  const fd = fs.openSync(path, 'r')
  const contents = fs.readFileSync(fd)
  fs.closeSync(fd)
  const text = contents.toString()
  return JSON.parse(text)
}

// tests

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

describe('argon2u', () => {
  it('works as expected', async function() {
    this.timeout(10000)

    let res = await kg.argon2u({entropy: 'my rad entropy'})

    expect(res).to.not.be.undefined
    expect('hash' in res).to.equal(true)
    expect(res.hash).to.have.lengthOf(32)
  })
})

describe('sha256', () => {
  it('produces 256-bit digests', () => {
    let prop = jsc.forall(jsc.string, async str => {
      let digest = await kg._sha256(str)
      return digest.byteLength === 32
    })
    jsc.assert(prop)
  })

  it('works as expected', async () => {
    let helloHash =
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

    let hash = await kg._sha256('hello')
    let hashHex = Buffer.from(hash).toString('hex')

    expect(hashHex).to.equal(helloHash)
  })
})

describe('childSeedFromSeed', () => {
  let types = lodash.values(kg.CHILD_SEED_TYPES)
  let nonNetworkSeedType = jsc.oneof(
    lodash.map(
      lodash.filter(types, type => type !== kg.CHILD_SEED_TYPES.NETWORK),
      jsc.constant
    ))

  let config = jsc.record({
    seed: jsc.string,
    type: nonNetworkSeedType,
    ship: jsc.oneof(jsc.uint32, jsc.constant(null)),
    revision: jsc.oneof(jsc.uint8, jsc.constant(null)),
    password: jsc.string
  })

  it('produces valid BIP39 mnemonics for non-network seeds', () => {
    let prop = jsc.forall(config, async cfg => {
      let child = await kg.childSeedFromSeed(cfg)
      return bip39.validateMnemonic(child)
    })
    jsc.assert(prop)
  })

  it('uses the ship to salt the parent seed, when present', () => {
    let prop = jsc.forall(config, async cfg0 => {
      let { seed, type, ship, revision } = cfg0
      let cfg1 = { seed, type, ship: null, revision }

      let child0 = await kg.childSeedFromSeed(cfg0)
      let child1 = await kg.childSeedFromSeed(cfg1)

      return lodash.isNull(ship)
        ? lodash.isEqual(child0, child1) === true
        : lodash.isEqual(child0, child1) === false
    })

    jsc.assert(prop)
  })

  it('uses the revision to salt the parent seed', () => {
    let prop = jsc.forall(config, async cfg0 => {
      let { seed, type, ship, revision } = cfg0
      let cfg1 = { seed, type, ship, revision: 257 }

      let child0 = await kg.childSeedFromSeed(cfg0)
      let child1 = await kg.childSeedFromSeed(cfg1)

      return lodash.isEqual(child0, child1) === false
    })

    jsc.assert(prop)
  })

  it('uses the seed type to salt the parent seed', () => {
    let prop = jsc.forall(config, async cfg0 => {
      let { seed, type, ship, revision } = cfg0
      let cfg1 = { seed, type: 'bollocks', ship, revision }

      let child0 = await kg.childSeedFromSeed(cfg0)
      let child1 = await kg.childSeedFromSeed(cfg1)

      return lodash.isEqual(child0, child1) === false
    })

    jsc.assert(prop)
  })

  it('works as expected', async () => {
    let cfg = {
      seed: 'my amazing seed',
      type: 'management',
      ship: 10,
      revision: 0,
    }

    let child = await kg.childSeedFromSeed(cfg)
    let mnemonic = 'embody arm since script grocery retire laptop task chunk exclude eyebrow minimum crouch security wish ceiling engage resist good rural illegal trophy imitate public'

    expect(child).to.equal(mnemonic)

    cfg = {
      seed: 'my amazing seed',
      type: 'ownership',
      ship: 10,
      revision: 0,
    }

    child = await kg.childSeedFromSeed(cfg)
    mnemonic = 'truth absent quiz metal just retreat large example excess okay lunch plate coast flat void rule input world skill duck zero again loan buddy'

    expect(child).to.equal(mnemonic)
  })
})

describe('bip32NodeFromSeed', () => {
  const mnemonicGenerator = _ => bip39.generateMnemonic()
  const mnemonic = jsc.nonshrink({
    generator: mnemonicGenerator,
    show: (a) => a
  })

  const VALID_PATH = "m/44'/60'/0'/0/0"
  const INVALID_PATH = "m/44'/60/0'/0/0"

  it('derives by paths correctly', () => {
    let prop = jsc.forall(mnemonic, mnem => {
      let seed = bip39.mnemonicToSeed(mnem)
      let hd = hdkey.fromMasterSeed(seed)
      let wallet0 = hd.derive(VALID_PATH)
      let wallet1 = hd.derive(INVALID_PATH)

      let node = kg.bip32NodeFromSeed(mnem)

      return wallet0.publicKey.toString('hex') === node.public
        && wallet0.privateKey.toString('hex') === node.private
        && wallet0.chainCode.toString('hex') === node.chain
        && wallet1.publicKey.toString('hex') !== node.public
        && wallet1.privateKey.toString('hex') !== node.private
        && wallet1.chainCode.toString('hex') !== node.chain
    })

    jsc.assert(prop)
  })

  it('has the correct properties', () => {
    let prop = jsc.forall(mnemonic, mnem => {
      let node = kg.bip32NodeFromSeed(mnem)

      return 'public' in node && 'private' in node && 'chain' in node
    })
  })

  it('works as expected', () => {
    let node = kg.bip32NodeFromSeed(
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
        '0x1A24D827E5fFC40A0C4E2174deFFbb22B3A80923'
    }

    expect(lodash.isEqual(node, expected)).to.equal(true)
  })
})

describe('urbitKeysFromSeed', () => {
  it('matches ++pit:nu:crub:crypto', () => {
    // ~zod:dojo> /+ keygen
    // ~zod:dojo> (urbit:sd:keygen (to-byts:keygen 'test'))

    let expected = {
      auth: {
        public: '27805022e91c06573e0e789a393921e7f417a43564ab39b7d9b036c39f0e180f',
        private: 'ec491815377abc52019230c575d29bcb4f288e0df5070c3dbb74c0822150c7ce'
      },
      crypt: {
        public: '8e2487a0e81314e4f9bc5edbb9de750e79e92d981e0cf4a27664244569dd06ba',
        private: '8b02ff5c5c36447ab4644cb5c37b5362c44fc19cceb8286c3fccbc11d92353a8'
      }
    }

    let seed = Buffer.from('test')
    let keys = kg.urbitKeysFromSeed(seed)

    expect(lodash.isEqual(keys, expected)).to.equal(true)

    seed = Buffer.from('some seed');
    keys = kg.urbitKeysFromSeed(seed)

    expected = {
      auth: {
        private: 'fd816b63558f3f4ee5eafedbabe56293ee1f64e837f081724bfdd47d6e4b9815',
        public: 'bbba375a6dd28dc9e44d6a98c75edeb699c10d78e92ccad78c892efa2466c666'
      },
      crypt: {
        private: '15ef9b020606faf25dd4b622d34a5f2ba83e3498f78e35c6d256379f4871391e',
        public: '220c0db4f436d2532f0fddb56555bf6926d6bcfb073d790b8f1e9c4258ebb43e'
      }
    }

    expect(lodash.isEqual(keys, expected)).to.equal(true)
  })

  it('contains the expected fields', () => {
    let prop = jsc.forall(jsc.string, str => {
      let keys = kg.urbitKeysFromSeed(Buffer.from(str))

      return 'auth' in keys && 'crypt' in keys
        && 'public' in keys.auth && 'private' in keys.auth
        && 'public' in keys.crypt && 'private' in keys.crypt
    })

    jsc.assert(prop, { tests: 50 })
  })
})

describe('ethereum addresses from keys', () => {
  let config = jsc.record({
    seed: jsc.nestring.smap((x) => Buffer.from(x), (x) => x.toString()),
    type: jsc.constant(kg.CHILD_SEED_TYPES.MANAGEMENT),
    revision: jsc.uint8,
    ship: jsc.uint32,
    password: jsc.string
  })

  it('matches when derived from public or private secp256k1 keys', () => {
    const secpConfig = lodash.cloneDeep(config)
    secpConfig.type = jsc.oneof(
        lodash.map(
          lodash.filter(lodash.values(kg.CHILD_SEED_TYPES), type =>
            type !== kg.CHILD_SEED_TYPES.NETWORK),
          jsc.constant))

    let matches = jsc.forall(secpConfig, async cfg => {
      let node = await kg.childNodeFromSeed(cfg)
      let addrPriv = kg.addressFromSecp256k1Private(node.keys.private)
      let addrPub = kg.addressFromSecp256k1Public(node.keys.public)
      return addrPriv === addrPub
    })

    jsc.assert(matches)
  })
})

describe('shard', () => {
  it('does not shard non-384-bit tickets', () => {
    let ticket = '~doznec-marbud'
    expect(kg.shard(ticket)).to.have.lengthOf(1)
  })

  it('shards 384-bit tickets', () => {
    let ticket = '~wacfus-dabpex-danted-mosfep-pasrud-lavmer-nodtex-taslus-pactyp-milpub-pildeg-fornev-ralmed-dinfeb-fopbyr-sanbet-sovmyl-dozsut-mogsyx-mapwyc-sorrup-ricnec-marnys-lignex'
    expect(kg.shard(ticket)).to.have.lengthOf(3)
  })
})

describe('generateWallet', () => {
  it('generates wallets', async function() {
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
      password: 'froot loops',
      revision: 6
    }
    wallet = await kg.generateWallet(config)
    expected = objectFromFile('./test/assets/wallet2.json')

    expect(lodash.isEqual(wallet, expected)).to.equal(true)

    config = {
      ticket: '~doznec-marbud',
    }
    wallet = await kg.generateWallet(config)
    expected = objectFromFile('./test/assets/wallet3.json')

    expect(lodash.isEqual(wallet, expected)).to.equal(true)

  })

})
