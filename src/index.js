const argon2 = require('argon2-wasm')
const bip32 = require('bip32')
const bip39 = require('bip39')
const jssha256 = require('js-sha256')
const keccak = require('keccak')
const nacl = require('tweetnacl')
const ob = require('urbit-ob')
const secp256k1 = require('secp256k1')
const noun = require('./nockjs/noun')
const serial = require('./nockjs/serial')
const BN = require('bn.js')

const { version, name } = require('../package.json')

const GALAXY_MIN = 0x00000000
const GALAXY_MAX = 0x000000ff
const PLANET_MIN = 0x00010000
const PLANET_MAX = 0xffffffff

const CHILD_SEED_TYPES = {
  OWNERSHIP: 'ownership',
  TRANSFER: 'transfer',
  SPAWN: 'spawn',
  VOTING: 'voting',
  MANAGEMENT: 'management',
  NETWORK: 'network',
  BITCOIN_MAINNET: 'bitcoinMainnet',
  BITCOIN_TESTNET: 'bitcoinTestnet'
}

const DERIVATION_PATH = "m/44'/60'/0'/0/0"
const BTC_MAINNET_DERIVATION_PATH = "m/84'/0'/0'"
const BTC_TESTNET_DERIVATION_PATH = "m/84'/1'/0'"

const BITCOIN_MAINNET_INFO = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'bc',
  bip32: {
    public: 0x04b24746,
    private: 0x04b2430c,
  },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
}

const BITCOIN_TESTNET_INFO = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'tb',
  bip32: {
    public: 0x045f1cf6,
    private: 0x045f18bc,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
}

const NETWORK_KEY_CURVE_PARAMETER = '42'

/**
 * Add a hex prefix to a string, if one isn't already present.
 *
 * @param  {String}  hex
 * @return  {String}
 */
const addHexPrefix = hex =>
  hex.slice(0, 2) === '0x'
  ? hex
  : '0x' + hex

/**
 * Strip a hex prefix from a string, if it's present.
 *
 * @param  {String}  hex
 * @return  {String}
 */
const stripHexPrefix = hex =>
  hex.slice(0, 2) === '0x'
  ? hex.slice(2)
  : hex

/**
 * Hex string into Buffer, accounting for leading 0x and missing leading zeroes,
 * crashing if hex is invalid.
 *
 * @param  {String} hex
 * @return  {Buffer}
 */
const hexToBuffer = hex => {
  let cleanHex = stripHexPrefix(hex)
  if (typeof cleanHex === 'string' && (cleanHex.length % 2) === 1) {
    cleanHex = '0' + cleanHex
  }
  const buf = Buffer.from(cleanHex, 'hex')
  if (cleanHex.length !== 0 && buf.length === 0) {
    throw new Error('invalid hex string: ' + hex)
  }
  return buf
}

/**
 * Base-64 encode a buffer.
 *
 * @param  {Buffer}  buf
 * @return  {String}
 */
const b64 = buf => {
  let hex = buf.reverse().toString('hex')
  let n = new BN(hex, 'hex')
  let c = []
  while (1 === n.cmpn(0)) {
    c.push(n.andln(0x3f))
    n = n.shrn(6)
  }

  const trans = j =>
    10 > j
    ? j + 48
    : 36 > j
    ? j + 87
    : 62 > j
    ? j + 29
    : 62 === j
    ? 45
    : 126

  return (
    '0w' +
    c.reduce(
      (a, b, i) =>
        String.fromCharCode(trans(b)) + (i && 0 === i % 5 ? '.' : '') + a,
      ''
    )
  )
}

/**
 * Jam a noun.
 *
 * @param  {Noun}  seed
 * @return  {Buffer}
 */
const jam = seed => {
  const hex = serial
    .jam(seed)
    .toString()
    .slice(2)
  const pad = hex.length % 2 === 0 ? hex : '0' + hex
  return Buffer.from(pad, 'hex').reverse()
}

/**
 * Keccak-256 hash function.
 *
 * @param  {String}  str
 * @return  {String}
 */
const keccak256 = str =>
  keccak('keccak256').update(str).digest()

/**
 * Convert an Ethereum address to a checksummed Ethereum address.
 *
 * @param  {String}  address an Ethereum address
 * @return  {String}  checksummed address
 */
const toChecksumAddress = (address) => {
  const addr = stripHexPrefix(address).toLowerCase()
  const hash = keccak256(addr).toString('hex')
  const arr = Array.from(addr)
  return arr.reduce((acc, char, idx) =>
    parseInt(hash[idx], 16) >= 8
      ? acc + char.toUpperCase()
      : acc + char,
    '0x'
  )
}

/**
 * Check if a ship is a galaxy.
 * @param  {Number}  ship
 * @return  {Bool}  true if galaxy, false otherwise
 */
const isGalaxy = ship =>
  Number.isInteger(ship) && ship >= GALAXY_MIN && ship <= GALAXY_MAX

/**
 * Check if a ship is a planet.
 * @param  {Number}  ship
 * @return  {Bool}  true if planet, false otherwise
 */
const isPlanet = ship =>
  Number.isInteger(ship) && ship >= PLANET_MIN && ship <= PLANET_MAX

/**
 * Convert a hex-encoded secp256k1 public key into an Ethereum address.
 *
 * @param  {String}  pub a 33-byte compressed and hex-encoded public key (i.e.,
 *                   including the leading parity byte)
 * @return  {String}  the corresponding Ethereum address
 */
const addressFromSecp256k1Public = pub => {
  const compressed = false
  const uncompressed = secp256k1.publicKeyConvert(
    hexToBuffer(pub),
    compressed
  )
  const chopped = uncompressed.slice(1) // chop parity byte
  const hashed = keccak256(chopped)
  const addr = addHexPrefix(hashed.slice(-20).toString('hex'))
  return toChecksumAddress(addr)
}

/**
 * Argon2 key derivation function, with parameters set as per UP8.
 *
 * The 'ship' argument is used to salt the provided entropy.
 *
 * @param  {Buffer}  entropy an entropy Buffer
 * @param  {Number}  ship a 32-bit Urbit ship number
 * @return {Promise<Uint8Array>} the derived master seed
 */
const argon2u = async (entropy, ship) => {
  const a2u = await argon2.hash({
    pass: entropy,
    salt: `urbitkeygen${ship}`,
    type: argon2.types.Argon2u,
    hashLen: 32,
    parallelism: 4,
    mem: 512000,
    time: 1,
  })
  return a2u.hash
}

/**
 * SHA-256 hash function.
 *
 * @param  {Array, ArrayBuffer, Buffer, String} args any number of arguments
 * @return {Buffer}  the hash, as bytes
 */
const sha256 = (...args) => {
  const buffer = Buffer.concat(args.map(x => Buffer.from(x)))
  const hashed = jssha256.sha256.array(buffer)
  return Buffer.from(hashed)
}

/**
 * Derive a BIP39 mnemonic (UP8 child 'seed') for the given node type, using
 * the provided master seed as entropy.
 *
 * @param  {Uint8Array}  master a master seed
 * @param  {String}  type one of 'ownership', 'transfer', 'spawn', 'voting',
 *                   'management', 'bitcoinTestnet', 'bitcoinMainnet'
 * @return  {String}  a BIP39 mnemonic
 *
 */
const deriveNodeSeed = (master, type) => {
  const hash = sha256(master, type)
  return bip39.entropyToMnemonic(hash)
}

/**
 * Derive a secp256k1 keypair and corresponding Ethereum address from a
 * mnemonic and optional passphrase, according to UP8.
 *
 * @param  {String}  mnemonic a BIP39 mnemonic
 * @param  {String}  derivationPath wallet derivation path
 * @param  {String}  passphrase an optional passphrase
 * @return  {Object}  the keypair, BIP32 chain code, and Ethereum address
 */
const deriveNodeKeys = (mnemonic, derivationPath, passphrase) => {
  const seed = bip39.mnemonicToSeed(mnemonic, passphrase)
  const hd = bip32.fromSeed(seed)
  const wallet = hd.derivePath(derivationPath)
  return {
    public: wallet.publicKey.toString('hex'),
    private: wallet.privateKey.toString('hex'),
    chain: wallet.chainCode.toString('hex'),
    address: addressFromSecp256k1Public(wallet.publicKey.toString('hex'))
  }
}

/**
 * Derive a child mnemonic and its associated secp256k1 keys from a master
 * seed, given the provided child type and an optional passphrase.
 *
 * @param  {Uint8Array}  master a master seed
 * @param  {String}  type one of 'ownership', 'transfer', 'spawn', 'voting',
 *                   'management', 'bitcoinTestnet', 'bitcoinMainnet'
 * @param  {String}  derivationPath wallet derivation path
 * @param  {String}  passphrase an optional passphrase
 * @return  {Object}  the child seed and associated keys
 */
const deriveNode = (master, type, derivationPath, passphrase) => {
  const mnemonic = deriveNodeSeed(master, type)
  const keys = deriveNodeKeys(mnemonic, derivationPath, passphrase)
  return {
    type: type,
    seed: mnemonic,
    keys: keys,
    derivationPath: derivationPath
  }
}

/**
 * Derive a network seed using the provided management mnemonic and optional
 * passphrase.  A provided revision number is also used as a salt.
 *
 * @param  {String}  mnemonic the management mnemonic
 * @param  {String}  passphrase an optional passphrase
 * @param  {Number}  revision a revision number
 * @return  {String}  the resulting hex-encoded network seed
 */
const deriveNetworkSeed = (mnemonic, passphrase, revision) => {
  const seed = bip39.mnemonicToSeed(mnemonic, passphrase)
  const hash = sha256(seed, CHILD_SEED_TYPES.NETWORK, `${revision}`)
  // SHA-256d on nonzero revisions to prevent length extension attacks
  const dhash = revision === 0 ? hash : sha256(hash)
  return dhash.toString('hex')
}

/**
 * Derive ed25519 Urbit network keys from the provided network seed.
 *
 * Note that this matches ++pit:nu:crub:crypto in zuse.
 *
 * @param  {String}  seed the hex-encoded network seed
 * @return  {Object}  ed25519 crypt and auth keys
 */
const deriveNetworkKeys = hex => {
  const seed = hexToBuffer(hex)
  let h = []
  nacl.lowlevel.crypto_hash(h, seed.reverse(), seed.length)

  const c = Buffer.from(h.slice(32))
  const a = Buffer.from(h.slice(0, 32))

  const crypt = nacl.sign.keyPair.fromSeed(c)
  const cpub  = Buffer.from(crypt.publicKey)
  const auth = nacl.sign.keyPair.fromSeed(a)
  const apub  = Buffer.from(auth.publicKey)

  return {
    crypt: {
      private: c.reverse().toString('hex'),
      public: cpub.reverse().toString('hex')
    },
    auth: {
      private: a.reverse().toString('hex'),
      public: apub.reverse().toString('hex')
    }
  }
}

/**
 * Derive a network seed and associated ed25519 keys from a management
 * mnemonic, revision, and optional passphrase.
 *
 * @param  {String}  mnemonic a management mnemonic
 * @param  {Number}  revision a revision number
 * @param  {String}  passphrase an optional passphrase
 * @return  {Object}  the network seed and associated keys
 */
const deriveNetworkInfo = (mnemonic, revision, passphrase) => {
  const seed = deriveNetworkSeed(mnemonic, passphrase, revision)
  const keys = deriveNetworkKeys(seed)
  return {
    type: CHILD_SEED_TYPES.NETWORK,
    seed: seed,
    keys: keys
  }
}

/**
 * Break a 384-bit ticket into three shards, any two of which can be used to
 * recover it.  Each shard is simply 2/3 of the ticket -- the first third,
 * second third, and first and last thirds concatenated together, respectively.
 *
 * If provided with a ticket of some other length, it simply returns the ticket
 * itself in an array.
 *
 * @param  {String}  ticket a 384-bit @q ticket
 * @return {Array<String>}  the resulting shards
 */
const shard = ticket => {
  const ticketHex = ob.patq2hex(ticket)
  const ticketBuf = hexToBuffer(ticketHex)

  if (ticketBuf.length !== 48) {
    return [ ticket ]
  }

  const shards = [
    ticketBuf.slice(0, 32),
    ticketBuf.slice(16),
    Buffer.concat([ ticketBuf.slice(0, 16), ticketBuf.slice(32) ])
  ]

  const pq = shards.map(shard => ob.hex2patq(shard.toString('hex')))

  const combinable =
    combine([pq[0], pq[1], undefined]) === ticket &&
    combine([pq[0], undefined, pq[2]]) === ticket &&
    combine([undefined, pq[1], pq[2]]) === ticket

  // shards should always be combinable, so following should be unreachable
  /* istanbul ignore next */
  if (combinable === false) {
    /* istanbul ignore next */
    throw new Error('produced invalid shards -- please report this as a bug')
  }

  return pq
}

/**
 * Combine two of three shards to recompute the original secret.
 *
 * @param  {Array<String>} shards an array of shards, in their appropriate
 *                         order; use 'undefined' to mark a missing shard,
 *                         e.g.
 *
 *                         > combine([shard0, undefined, shard2])
 *
 * @return {String} the original secret
 */
const combine = shards => {
  const nundef = shards.reduce((acc, shard) =>
    acc + (shard === undefined ? 1 : 0), 0)

  if (nundef > 1) {
    throw new Error('combine: need at least two shards')
  }

  const s0 = shards[0]
  const s1 = shards[1]
  const s2 = shards[2]

  return ob.hex2patq(
      s0 !== undefined && s1 !== undefined
    ? ob.patq2hex(s0).slice(0, 32) + ob.patq2hex(s1)
    : s0 !== undefined && s2 !== undefined
    ? ob.patq2hex(s0) + ob.patq2hex(s2).slice(32)
    : s1 !== undefined && s2 !== undefined
    ? ob.patq2hex(s2).slice(0, 32) + ob.patq2hex(s1)
    // above throw makes this unreachable
    /* istanbul ignore next */
    : undefined
  )
}

/**
 * Generate a keyfile corresponding to a keypair, point, and revision.
 *
 * @param {Object} pair
 * @param {Number} point
 * @param {Number} revision
 * @return {String}
 */
const generateKeyfile = (pair, point, revision) => {

  const ring  =
    pair.crypt.private + pair.auth.private + NETWORK_KEY_CURVE_PARAMETER

  const bnsec = new BN(ring, 'hex')

  const sed = noun.dwim(
    noun.Atom.fromInt(point),
    noun.Atom.fromInt(revision),
    noun.Atom.fromString(bnsec.toString()),
    noun.Atom.yes
  )

  return b64(jam(sed))
}

/**
 * Generate just the ownership branch of an Urbit HD wallet given the
 * provided configuration.
 *
 * Expects an object with the following properties:
 *
 * @param  {String}  ticket a 64, 128, or 384-bit @q master ticket
 * @param  {Number}  ship a 32-bit Urbit ship number
 * @param  {String}  passphrase an optional passphrase to use when deriving
 *                   seeds from BIP39 mnemonics
 * @return  {Promise<Object>}
 */
const generateOwnershipWallet = async config => {
  /* istanbul ignore next */
  if ('ticket' in config === false) {
    throw new Error('generateWallet: no ticket provided')
  }
  /* istanbul ignore next */
  if ('ship' in config === false) {
    throw new Error('generateWallet: no ship provided')
  }

  const { ticket, ship } = config
  const passphrase = 'passphrase' in config ? config.passphrase : null

  const buf = hexToBuffer(ob.patq2hex(ticket))
  const masterSeed = await argon2u(buf, ship)

  const node = deriveNode(
    masterSeed,
    CHILD_SEED_TYPES.OWNERSHIP,
    DERIVATION_PATH,
    passphrase
  )

  return node
}

/**
 * Generate an Urbit HD wallet given the provided configuration.
 *
 * Expects an object with the following properties:
 *
 * @param  {String}  ticket a 64, 128, or 384-bit @q master ticket
 * @param  {Number}  ship a 32-bit Urbit ship number
 * @param  {String}  passphrase an optional passphrase to use when deriving
 *                   seeds from BIP39 mnemonics
 * @param  {Number}  revision an optional revision number used to generate new
 *                   networking keys (defaults to 0)
 * @param  {Bool}  boot if true, generates network keys for the provided ship
 *                 (defaults to false)
 * @return  {Promise<Object>}
 */
const generateWallet = async config => {
  /* istanbul ignore next */
  if ('ticket' in config === false) {
    throw new Error('generateWallet: no ticket provided')
  }
  /* istanbul ignore next */
  if ('ship' in config === false) {
    throw new Error('generateWallet: no ship provided')
  }

  const { ticket, ship } = config

  const passphrase = 'passphrase' in config ? config.passphrase : null
  const revision = 'revision' in config ? config.revision : 0
  const boot = 'boot' in config ? config.boot : false

  const shards = shard(ticket)

  const patp = ob.patp(ship)
  const tier = ob.clan(patp)

  const buf = hexToBuffer(ob.patq2hex(ticket))

  const meta = {
    generator: {
      name: name,
      version: version,
    },
    spec: "UP8",
    ship: ship,
    patp: patp,
    tier: tier,
    passphrase: passphrase
  }

  const masterSeed = await argon2u(buf, ship)

  const ownership = deriveNode(
    masterSeed,
    CHILD_SEED_TYPES.OWNERSHIP,
    DERIVATION_PATH,
    passphrase
  )

  const transfer = deriveNode(
    masterSeed,
    CHILD_SEED_TYPES.TRANSFER,
    DERIVATION_PATH,
    passphrase
  )

  const spawn =
      !isPlanet(ship)
    ? deriveNode(
        masterSeed,
        CHILD_SEED_TYPES.SPAWN,
        DERIVATION_PATH,
        passphrase
      )
    : {}

  const voting =
      isGalaxy(ship)
    ? deriveNode(
        masterSeed,
        CHILD_SEED_TYPES.VOTING,
        DERIVATION_PATH,
        passphrase
      )
    : {}

  const management = deriveNode(
    masterSeed,
    CHILD_SEED_TYPES.MANAGEMENT,
    DERIVATION_PATH,
    passphrase
  )

  const network =
      boot === true
    ? deriveNetworkInfo(
        management.seed,
        revision,
        passphrase
      )
    : {}

  const bitcoinTestnet = deriveNode(
    masterSeed,
    CHILD_SEED_TYPES.BITCOIN_TESTNET,
    BTC_TESTNET_DERIVATION_PATH,
    passphrase
  )

  bitcoinTestnet.keys =
    {
      xpub: bip32.fromPublicKey(Buffer.from(bitcoinTestnet.keys.public, 'hex'),
                                Buffer.from(bitcoinTestnet.keys.chain, 'hex'),
                                BITCOIN_TESTNET_INFO)
        .toBase58(),

      xprv: bip32.fromPrivateKey(Buffer.from(bitcoinTestnet.keys.private, 'hex'),
                                 Buffer.from(bitcoinTestnet.keys.chain, 'hex'),
                                 BITCOIN_TESTNET_INFO)
        .toBase58()
    }

  const bitcoinMainnet = deriveNode(
    masterSeed,
    CHILD_SEED_TYPES.BITCOIN_MAINNET,
    BTC_MAINNET_DERIVATION_PATH,
    passphrase
  )

  bitcoinMainnet.keys =
    {
      xpub: bip32.fromPublicKey(Buffer.from(bitcoinMainnet.keys.public, 'hex'),
                                Buffer.from(bitcoinMainnet.keys.chain, 'hex'),
                                BITCOIN_MAINNET_INFO)
        .toBase58(),
      xprv: bip32.fromPrivateKey(Buffer.from(bitcoinMainnet.keys.private, 'hex'),
                                 Buffer.from(bitcoinMainnet.keys.chain, 'hex'),
                                 BITCOIN_MAINNET_INFO)
        .toBase58()
    }

  return {
    meta: meta,
    ticket: ticket,
    shards: shards,
    ownership: ownership,
    transfer: transfer,
    spawn: spawn,
    voting: voting,
    management: management,
    network: network,
    bitcoinTestnet: bitcoinTestnet,
    bitcoinMainnet: bitcoinMainnet
  }
}

module.exports = {
  generateWallet,
  generateOwnershipWallet,
  deriveNode,
  deriveNodeSeed,
  deriveNodeKeys,
  deriveNetworkInfo,
  deriveNetworkSeed,
  deriveNetworkKeys,
  CHILD_SEED_TYPES,
  argon2u,
  shard,
  combine,
  addressFromSecp256k1Public,

  _isGalaxy: isGalaxy,
  _isPlanet: isPlanet,
  _sha256: sha256,
  _keccak256: keccak256,
  _toChecksumAddress: toChecksumAddress,
  _addHexPrefix: addHexPrefix,
  _stripHexPrefix: stripHexPrefix
}
