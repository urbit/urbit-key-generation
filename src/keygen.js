const argon2 = require('argon2-wasm')
const bip39 = require('bip39');
const crypto = require('isomorphic-webcrypto');
const hdkey = require('hdkey');
const lodash = require('lodash');
const nacl = require('tweetnacl');
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
  return bip39.entropyToMnemonic(hash)
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
    keys: await bip32NodeFromSeed(child, password)
  }
}



/**
 * Derive a BIP32 master node from a seed.
 *
 * @param  {String}  seed a BIP39 mnemonic
 * @param  {String}  password an optional password to use when generating the
 *   BIP39 seed
 * @return {Promise<Object>} a BIP32 node
 */
const bip32NodeFromSeed = async (mnemonic, password) => {
  const seed = bip39.mnemonicToSeed(mnemonic, password)
  const hd = hdkey.fromMasterSeed(seed)
  const path = "m/44'/60'/0'/0/0"
  const wallet = hd.derive(path)
  return {
    public: buf2hex(wallet.publicKey),
    private: buf2hex(wallet.privateKey),
    chain: buf2hex(wallet.chainCode),
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
      public: buf2hex(crypt.publicKey.reverse()),
    },
    auth: {
      private: buf2hex(a.reverse()),
      public: buf2hex(auth.publicKey.reverse()),
    }
  }
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
  const ship = 'ship' in config ? config[ship] : null
  const password = 'password' in config ? config[password] : null
  const revision = 'revision' in config ? config[revision] : 0
  const boot = 'boot' in config ? config[boot] : false

  const ticketHex = ob.patq2hex(ticket)
  const ticketBuf = Buffer.from(ticketHex, 'hex')
  const hashedTicket = await argon2u(ticketBuf)

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
    isGalaxy(ship) === false
    ? {}
    : await childNodeFromSeed({
        seed: masterSeed,
        type: CHILD_SEED_TYPES.VOTING,
        ship: ship,
        revision: revision,
        password: password
      })

  const management = await childNodeFromSeed({
      seed: masterSeed,
      type: CHILD_SEED_TYPES.MANAGEMENT,
      ship: ship,
      revision: revision,
      password: password
    })

  const network = {}

  if (boot === true) {
    let networkSeed = await childSeedFromSeed({
      seed: bip39.mnemonicToSeed(management.seed),
      type: CHILD_SEED_TYPES.NETWORK,
      ship: ship,
      revision: revision,
      password: password
    })

    lodash.assign(network, {
      seed: networkSeed,
      keys: urbitKeysFromSeed(networkSeed),
      meta: {
        type: CHILD_SEED_TYPES.NETWORK,
        revision: revision,
        ship: ship
      }
    })
  }

  return {
    ticket: ticket,
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
  childNodeFromSeed
}


