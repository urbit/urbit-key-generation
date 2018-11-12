const argon2 = require('argon2-wasm')
const bip32 = require('bip32')
const bip39 = require('bip39')
const crypto = require('isomorphic-webcrypto')
const keccak = require('keccak')
const lodash = require('lodash')
const nacl = require('tweetnacl')
const ob = require('urbit-ob')
const secp256k1 = require('secp256k1')

const CHILD_SEED_TYPES = {
  OWNERSHIP: 'ownership',
  TRANSFER: 'transfer',
  SPAWN: 'spawn',
  VOTING: 'voting',
  MANAGEMENT: 'management',
  NETWORK: 'network'
}

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

  return lodash.reduce(addr, (acc, char, idx) =>
    parseInt(hash[idx], 16) >= 8
      ? acc + char.toUpperCase()
      : acc + char,
    '0x')
}

/**
 * Check if a ship is a galaxy.
 * @param  {Number}  ship
 * @return  {Bool}  true if galaxy, false otherwise
 */
const isGalaxy = ship =>
  lodash.isInteger(ship) && ship >= 0 && ship < 256

/**
 * Encode a buffer as hex.
 * @param  {Buffer}  buffer
 * @return  {String}  hex-encoded buffer
 */
const buf2hex = buffer => {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}


/**
 * Derive a 256-bit key from provided entropy via Argon2.
 *
 * @param  {String}  entropy
 * @return {Promise<Object>} derived key
 */
const argon2u = entropy => argon2.hash({
  pass: entropy,
  salt: 'urbitkeygen',
  type: argon2.types.Argon2u,
  hashLen: 32,
  parallelism: 4,
  mem: 512000,
  time: 1,
})

/**
 * SHA-256 hash function.
 *
 * @param  {Array, ArrayBuffer, Buffer, String} args any number of arguments
 * @return {Promise<ArrayBuffer>}  the hash, as bytes
 */
const sha256 = async (...args) => {
  const buffer = Buffer.concat(args.map(Buffer.from))
  return crypto.subtle.digest({ name: 'SHA-256' }, buffer)
}

/**
 * Derive a child seed from a parent.
 *
 * @param  {Array, ArrayBuffer, Buffer, String}  seed a parent seed
 * @param  {String}  type the type of child seed to derive
 * @return {Promise<String>} the child seed
 */
const childSeed = async config => {
  const { seed, type } = config
  const hash = await sha256(seed, type)
  return bip39.entropyToMnemonic(hash)
}

/**
 * Derive a child seed from a parent.
 *
 * @param  {Array, ArrayBuffer, Buffer, String}  seed a parent seed
 * @param  {String}  type the type of child seed to derive
 * @return {Promise<String>} the child seed
 */
const networkSeed = async config => {
  const { seed, type, index } = config
  const hash = await sha256(seed, type, `${index}`)
  return Buffer.from(hash).toString('hex')
}

/**
 * Create metadata for a BIP32 node.
 *
 * @param  {String}  type type of node being derived
 * @param  {Number}  index BIP44 index of the node being derived
 * @param  {Number}  ship ship number of the node being derived
 * @return  {Object}
 */
const nodeMetadata = (type, index, ship) => ({
  type: type,
  index: lodash.isUndefined(index) || lodash.isNull(index) ? 0 : index,
  ship: lodash.isUndefined(ship) ? null : ship
})

/**
 * Derive a child BIP32 node from a parent seed.
 *
 * @param  {Array, ArrayBuffer, Buffer, String}  seed a parent seed
 * @param  {String}  type the type of child node to derive
 * @param  {Number}  ship the ship to derive the node for
 * @param  {Number}  index the BIP44 index
 * @return {Promise<Object>} the BIP32 child node
 */
const childNode = async config => {
  const { type, ship, index, password } = config
  const child = await childSeed(config)
  return {
    meta: nodeMetadata(type, index, ship),
    seed: child,
    keys: bip32NodeFromSeed(child, password, index)
  }
}



/**
 * Derive a BIP32 master node -- supplemented with a corresponding Ethereum
 * address -- from a seed.
 *
 * @param  {String}  seed a BIP39 mnemonic
 * @param  {String}  password an optional password to use when generating the
 *   BIP39 seed
 * @param  {Number}  index the 'index' path, as per BIP44 (defaults to 0)
 * @return {Object} a BIP32 node
 */
const bip32NodeFromSeed = (mnemonic, password, index) => {

  index = lodash.isUndefined(index) || lodash.isNull(index) ? 0 : index

  const seed = bip39.mnemonicToSeed(mnemonic, password)
  const hd = bip32.fromSeed(seed)
  const wallet = hd.derivePath(`m/44'/60'/0'/0/${index}`)

  const publicKey = buf2hex(wallet.publicKey)
  const privateKey = buf2hex(wallet.privateKey)
  const chain = buf2hex(wallet.chainCode)
  const address = addressFromSecp256k1Public(publicKey)

  return {
    public: publicKey,
    private: privateKey,
    chain,
    address
  }
}



/**
 * Derive Urbit network keypairs from a seed.  Matches ++pit:nu:crub:crypto
 * @param  {Buffer} seed     seed to derive from
 * @return {Object} resulting Urbit network keys
 */
const urbitKeysFromSeed = seed => {
  let h = []
  nacl.lowlevel.crypto_hash(h, seed.reverse(), seed.length)

  const c = h.slice(32)
  const a = h.slice(0, 32)

  const crypt = nacl.sign.keyPair.fromSeed(Buffer.from(c))
  const auth = nacl.sign.keyPair.fromSeed(Buffer.from(a))

  return {
    crypt: {
      private: buf2hex(c.reverse()),
      public: buf2hex(crypt.publicKey.reverse())
    },
    auth: {
      private: buf2hex(a.reverse()),
      public: buf2hex(auth.publicKey.reverse())
    }
  }
}



/**
 * Convert a hex-encoded secp256k1 public key into an Ethereum address.
 *
 * @param  {String}  pub a 33-byte compressed and hex-encoded public key (i.e.,
 *   including the leading parity byte)
 * @return  {String}  the corresponding Ethereum address
 */
const addressFromSecp256k1Public = pub => {
  const compressed = false
  const uncompressed = secp256k1.publicKeyConvert(
    Buffer.from(pub, 'hex'),
    compressed
  )
  const chopped = uncompressed.slice(1) // chop parity byte
  const hashed = keccak256(chopped)
  const addr = addHexPrefix(hashed.slice(-20).toString('hex'))
  return toChecksumAddress(addr)
}



/**
 * Convert a hex-encoded secp256k1 private key into an Ethereum address.
 * @param  {String}  priv a 32-byte hex-encoded private key
 * @return  {String}  the corresponding Ethereum address
 */
const addressFromSecp256k1Private = priv => {
  const pub = secp256k1.publicKeyCreate(Buffer.from(priv, 'hex'))
  return addressFromSecp256k1Public(pub)
}



/**
 * Break a 384-bit ticket into three shards, any two of which can be used to
 * recover it.  If provided with a ticket of some other length, it simply
 * returns the ticket itself in an array.
 *
 * Each shard is simply 2/3 of the ticket -- the first third, second third, and
 * first and last thirds concatenated together.
 *
 * @param  {String} ticket a 384-bit @q ticket
 * @return {Array<String>}
 */
const shard = ticket => {
  const ticketHex = ob.patq2hex(ticket)
  const ticketBuf = Buffer.from(ticketHex, 'hex')

  if (ticketBuf.length !== 48) {
    return [ ticket ]
  }

  const shards = [
    ticketBuf.slice(0, 32),
    ticketBuf.slice(16),
    Buffer.concat([ ticketBuf.slice(0, 16), ticketBuf.slice(32) ])
  ]

  const pq = lodash.map(shards,
    shard => ob.hex2patq(shard.toString('hex')))

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
 *   order; use 'undefined' to mark a missing shard, e.g.
 *
 *   > combine([shard0, undefined, shard2])
 *
 * @return {String} the original secret
 */
const combine = shards => {
  const nundef = lodash.reduce(shards, (acc, shard) =>
    acc + (lodash.isUndefined(shard) ? 1 : 0), 0)

  if (nundef > 1) {
    throw new Error('combine: need at least two shards')
  }

  const s0 = shards[0]
  const s1 = shards[1]
  const s2 = shards[2]

  return ob.hex2patq(
      lodash.isUndefined(s0) === false && lodash.isUndefined(s1) === false
    ? ob.patq2hex(s0).slice(0, 32) + ob.patq2hex(s1)
    : lodash.isUndefined(s0) === false && lodash.isUndefined(s2) === false
    ? ob.patq2hex(s0) + ob.patq2hex(s2).slice(32)
    : lodash.isUndefined(s1) === false && lodash.isUndefined(s2) === false
    ? ob.patq2hex(s2).slice(0, 32) + ob.patq2hex(s1)
    // above throw makes this unreachable
    /* istanbul ignore next */
    : undefined
  )
}



/**
 * Generate an Urbit HD wallet given the provided configuration.
 *
 * @param  {String}  ticket a 64, 128, or 384-bit @q master ticket
 * @param  {Number}  ship an optional ship number
 * @param  {String}  password a password used to salt generated seeds (default:
 *   null)
 * @param  {Number}  index a BIP44 index (default: 0)
 * @param  {Bool}  boot if true, generate network keys for the provided ship
 *   (default: false)
 * @return  {Promise<Object>}
 */
const generateWallet = async config => {
  const { ticket } = config
  const ship = 'ship' in config ? config.ship : null
  const password = 'password' in config ? config.password : null
  const index = 'index' in config ? config.index : 0
  const boot = 'boot' in config ? config.boot : false

  const ticketHex = ob.patq2hex(ticket)
  const ticketBuf = Buffer.from(ticketHex, 'hex')
  const hashedTicket = await argon2u(ticketBuf)

  const shards = shard(ticket)

  const masterSeed = hashedTicket.hash

  const ownership = await childNode({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.OWNERSHIP,
      ship: ship,
      index: index,
      password: password
    })

  const transfer = await childNode({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.TRANSFER,
      ship: ship,
      index: index,
      password: password
    })

  const spawn = await childNode({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.SPAWN,
      ship: ship,
      index: index,
      password: password
    })

  const voting =
    isGalaxy(ship)
    ? await childNode({
        seed: masterSeed,
        type: CHILD_SEED_TYPES.VOTING,
        ship: ship,
        index: index,
        password: password
      })
    : {}

  const management = await childNode({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.MANAGEMENT,
      ship: ship,
      index: index,
      password: password
    })

  const network = {}

  if (boot === true) {
    let seed = await networkSeed({
      seed: bip39.mnemonicToSeed(management.seed, password),
      type: CHILD_SEED_TYPES.NETWORK,
      index: index
    })

    lodash.assign(network, {
      seed: seed,
      keys: urbitKeysFromSeed(Buffer.from(seed, 'hex')),
      meta: nodeMetadata(CHILD_SEED_TYPES.NETWORK, index, ship)
    })
  }

  return {
    ticket: ticket,
    shards: shards,
    ownership: ownership,
    transfer: transfer,
    spawn: spawn,
    voting: voting,
    management: management,
    network: network
  }
}

module.exports = {
  generateWallet,
  childSeed,
  childNode,
  bip32NodeFromSeed,
  urbitKeysFromSeed,
  CHILD_SEED_TYPES,
  argon2u,
  shard,
  combine,
  addressFromSecp256k1Public,
  addressFromSecp256k1Private,

  _isGalaxy: isGalaxy,
  _sha256: sha256,
  _keccak256: keccak256,
  _nodeMetadata: nodeMetadata,
  _toChecksumAddress: toChecksumAddress,
  _addHexPrefix: addHexPrefix,
  _stripHexPrefix: stripHexPrefix
}
