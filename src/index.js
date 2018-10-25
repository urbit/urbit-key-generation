const argon2 = require('argon2-wasm')
const bip39 = require('bip39')
const crypto = require('isomorphic-webcrypto')
const util = require('ethereumjs-util')
const hdkey = require('hdkey')
const lodash = require('lodash')
const nacl = require('tweetnacl')
const ob = require('urbit-ob')

const CHILD_SEED_TYPES = {
  OWNERSHIP: 'ownership',
  TRANSFER: 'transfer',
  SPAWN: 'spawn',
  VOTING: 'voting',
  MANAGEMENT: 'management',
  NETWORK: 'network'
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
 * @param  {Number}  ship the ship to derive the seed for
 * @param  {Number}  revision the revision number
 * @return {Promise<String>} the BIP39 child mnemonic
 */
const childSeedFromSeed = async config => {
  const { seed, type, ship, revision } = config
  const salt = lodash.isNull(ship) ? '' : `${ship}`
  const hash = await sha256(seed, type, salt, `${revision}`)
  return type !== CHILD_SEED_TYPES.NETWORK
    ? bip39.entropyToMnemonic(hash)
    : Buffer.from(hash).toString('hex')
}



/**
 * Derive a child BIP32 node from a parent seed.
 *
 * @param  {Array, ArrayBuffer, Buffer, String}  seed a parent seed
 * @param  {String}  type the type of child node to derive
 * @param  {Number}  ship the ship to derive the node for
 * @param  {Number}  revision the revision number
 * @return {Promise<Object>} the BIP32 child node
 */
const childNodeFromSeed = async config => {
  const { type, ship, revision, password } = config
  const child = await childSeedFromSeed(config)
  return {
    meta: {
      type: type,
      revision: revision,
      ship: ship
    },
    seed: child,
    keys: bip32NodeFromSeed(child, password)
  }
}



/**
 * Derive a BIP32 master node -- supplemented with a corresponding Ethereum
 * address -- from a seed.
 *
 * @param  {String}  seed a BIP39 mnemonic
 * @param  {String}  password an optional password to use when generating the
 *   BIP39 seed
 * @return {Object} a BIP32 node
 */
const bip32NodeFromSeed = (mnemonic, password) => {
  const seed = bip39.mnemonicToSeed(mnemonic, password)
  const hd = hdkey.fromMasterSeed(seed)
  const path = "m/44'/60'/0'/0/0"
  const wallet = hd.derive(path)

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

  const crypt_pub = buf2hex(crypt.publicKey.reverse())
  const auth_pub = buf2hex(auth.publicKey.reverse())

  return {
    crypt: {
      private: buf2hex(c.reverse()),
      public: crypt_pub,
      address: addressFromNetworkPublic(crypt_pub)
    },
    auth: {
      private: buf2hex(a.reverse()),
      public: auth_pub,
      address: addressFromNetworkPublic(auth_pub)
    }
  }
}



/**
 * Convert a hex-encoded secp256k1 public key into an Ethereum address.
 * @param  {String}  pub a (compressed) hex-encoded public key
 * @return  {String}  the corresponding Ethereum address
 */
const addressFromSecp256k1Public = pub => {
  const hashed = util.keccak256(Buffer.from(pub, 'hex'))
  const addr = util.addHexPrefix(hashed.slice(12).toString('hex'))
  return util.toChecksumAddress(addr)
}



/**
 * Convert a hex-encoded secp256k1 private key into an Ethereum address.
 * @param  {String}  pub a hex-encoded private key
 * @return  {String}  the corresponding Ethereum address
 */
const addressFromSecp256k1Private = priv => {
  const pub = util.secp256k1.publicKeyCreate(Buffer.from(priv, 'hex'))
  return addressFromSecp256k1Public(pub)
}



/**
 * Convert a hex-encoded Ed25519-variant Urbit public network key into an
 * Ethereum address.
 * @param  {String}  pub a hex-encoded public key
 * @return  {String}  the corresponding Ethereum address
 */
const addressFromNetworkPublic = pub => {
  const hashed = util.keccak256(Buffer.from(pub, 'hex'))
  const addr = util.addHexPrefix(hashed.slice(12).toString('hex'))
  return util.toChecksumAddress(addr)
}



/**
 * Break a 384-bit ticket into three shards, any two of which can be used to
 * recover it.
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

  const shard0 = ticketBuf.slice(0, 32)
  const shard1 = ticketBuf.slice(16)
  const shard2 = Buffer.concat([
    ticketBuf.slice(0, 16),
    ticketBuf.slice(32)
  ])

  return lodash.map([shard0, shard1, shard2], buf =>
    ob.hex2patq(buf.toString('hex')))
}



/**
 * Generate an Urbit HD wallet given the provided configuration.
 *
 * @param  {String}  ticket a 64, 128, or 384-bit @q master ticket
 * @param  {Number}  ship an optional ship number
 * @param  {String}  password a password used to salt generated seeds (default:
 *   null)
 * @param  {Number}  revision a revision number used as a salt (default: 0)
 * @param  {Bool}  boot if true, generate network keys for the provided ship
 *   (default: false)
 * @return  {Promise<Object>}
 */
const generateWallet = async config => {
  const { ticket } = config
  const ship = 'ship' in config ? config.ship : null
  const password = 'password' in config ? config.password : null
  const revision = 'revision' in config ? config.revision : 0
  const boot = 'boot' in config ? config.boot : false

  const ticketHex = ob.patq2hex(ticket)
  const ticketBuf = Buffer.from(ticketHex, 'hex')
  const hashedTicket = await argon2u(ticketBuf)

  const shards = shard(ticket)

  const masterSeed = hashedTicket.hash

  const ownership = await childNodeFromSeed({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.OWNERSHIP,
      ship: ship,
      revision: revision,
      password: password
    })

  const transfer = await childNodeFromSeed({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.TRANSFER,
      ship: ship,
      revision: revision,
      password: password
    })

  const spawn = await childNodeFromSeed({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.SPAWN,
      ship: ship,
      revision: revision,
      password: password
    })

  const voting =
    isGalaxy(ship)
    ? await childNodeFromSeed({
        seed: masterSeed,
        type: CHILD_SEED_TYPES.VOTING,
        ship: ship,
        revision: revision,
        password: password
      })
    : {}

  const management = await childNodeFromSeed({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.MANAGEMENT,
      ship: ship,
      revision: revision,
      password: password
    })

  const network = {}

  if (boot === true) {
    let seed = await childSeedFromSeed({
      seed: bip39.mnemonicToSeed(management.seed),
      type: CHILD_SEED_TYPES.NETWORK,
      ship: ship,
      revision: revision
    })

    lodash.assign(network, {
      seed: seed,
      keys: urbitKeysFromSeed(Buffer.from(seed, 'hex')),
      meta: {
        type: CHILD_SEED_TYPES.NETWORK,
        revision: revision,
        ship: ship
      }
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
  childSeedFromSeed,
  childNodeFromSeed,

  _isGalaxy: isGalaxy,
  _argon2u: argon2u,
  _sha256: sha256,
  _CHILD_SEED_TYPES: CHILD_SEED_TYPES,
  _bip32NodeFromSeed: bip32NodeFromSeed,
  _urbitKeysFromSeed: urbitKeysFromSeed,
  _shard: shard,
  _addressFromSecp256k1Public: addressFromSecp256k1Public,
  _addressFromSecp256k1Private: addressFromSecp256k1Private,
  _addressFromNetworkPublic: addressFromNetworkPublic
}
