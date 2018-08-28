import crypto from 'isomorphic-webcrypto'
import argon2 from 'argon2-wasm'
import nacl from 'tweetnacl'
import bip32 from 'bip32'

const bufferFrom = arr => Buffer.from(arr)

const bufferConcat = arr => Buffer.concat(arr)

const reverse = arr => arr.reverse()

const defaultTo = (any, d) => isUndefined(any) ? d : any

const get = (o, k, d) => {
  if (isUndefined(o)) return d
  const r = o[k]
  return isUndefined(r) ? d : r
}

const isUndefined = any => typeof any === 'undefined'

const buf2hex = buffer => {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

const hash = (...args) => {
  // map args into buffers and concat into one buffer
  const buffer = bufferConcat(args.map(a => bufferFrom(a)))
  // generate a SHA-512 hash from input buffer
  return crypto.subtle.digest({ name: 'SHA-512' }, buffer)
}



const argon2u = (entropy, ticketSize) => argon2({
  pass: entropy, // string or Uint8Array
  salt: 'urbitkeygen',
  type: 10, // argon2.ArgonType.Argon2u,
  hashLen: ticketSize,
  // distPath: 'node_modules/argon2-wasm/dist',
  parallelism: 4,
  mem: 512000,
  time: 1,
})



const childSeedFromSeed = async config =>  {
  const { seed, type, revision, ship, password } = config

  // let salt = `${type}-${revision}`
  // if (typeof ship === 'number') salt = `${salt}-${ship}`

  const salt = typeof ship === 'number'
    ? `${type}-${revision}-${ship}`
    : `${type}-${revision}`

  const childSeed = await hash(seed, salt, defaultTo(password, ''))

  return childSeed.slice(0, seed.length || seed.byteLength)
}


const walletFromSeed = async (seed, password) => {
  // we hash the seed with SHA-512 before doing BIP32 wallet generation,
  // because BIP32 doesn't support seeds of bit-lengths < 128 or > 512.

  const seedHash = await hash(seed, defaultTo(password, ''))

  const { publicKey, privateKey, chainCode } = bip32.fromSeed(bufferFrom(seedHash))

  return {
    public: buf2hex(publicKey),
    private: buf2hex(privateKey),
    chain: buf2hex(chainCode),
  }
}

const naclHash = seed => {
  let newHash = []
  nacl.lowlevel.crypto_hash(newHash, seed.reverse(), seed.length)
  return newHash
}


// matches ++pit:nu:crub:crypto
const urbitKeysFromSeed = (seed, password) => {
  const h = naclHash(bufferConcat([seed, password]))

  const c = h.slice(32)
  const a = h.slice(0, 32)

  const crypt = nacl.sign.keyPair.fromSeed(bufferFrom(c))
  const auth = nacl.sign.keyPair.fromSeed(bufferFrom(a))

  return {
    crypt: {
      private: buf2hex(reverse(c)),
      public: buf2hex(reverse(crypt.publicKey)),
    },
    auth: {
      private: buf2hex(reverse(a)),
      public: buf2hex(reverse(auth.publicKey)),
    },
  }
}


const childNodeFromSeed = async config => {
  const { seed, type, revision, ship, password } = config
  const childSeed = await childSeedFromSeed({seed, type, revision, ship, password})
  const childSeedBuffer = buf2hex(childSeed)
  return {
    meta: {
      type,
      revision: defaultTo(revision, 0),
      ship: !isUndefined(ship)
        ? ship
        : null
    },
    seed: childSeedBuffer,
    keys: await walletFromSeed(childSeedBuffer, password),
  }
}


const fullWalletFromTicket = async config => {
  const { ticket, seedSize, ships, password, revs } = config
  const seed = await argon2u(ticket, seedSize).hash
  return fullWalletFromSeed(bufferFrom(seed), ships, password, revs)
}


const fullWalletFromSeed = async config => {
  const { ownerSeed, ships, password, revisions } = config

  // Normalize revisions object
  const _revisions = {
    transfer: get(revisions, 'transfer', 0),
    spawn: get(revisions, 'spawn', 0),
    delegate: get(revisions, 'delegate', 0),
    manage: get(revisions, 'manage', 0),
    network: get(revisions, 'network', 0),
  }

  const ownershipNode = await childNodeFromSeed({
    seed: ownerSeed,
    type: 'owner',
    revision: null,
    ship: null,
    password: password,
  })

  const managementNode = await childNodeFromSeed({
    seed: ownerSeed,
    type: 'manage',
    revision: _revisions.manage,
    ship: null,
    password: password,
  })

  const delegateNode = await childNodeFromSeed({
    seed: ownerSeed,
    type: 'delegate',
    revision: _revisions.delegate,
    ship: null,
    password: password,
  })

  const transferNodes = await Promise.all(ships.map(ship => childNodeFromSeed({
    seed: ownerSeed,
    type: 'transfer',
    revision: _revisions.transfer,
    ship: ship,
    password: password,
  })))

  const spawnNodes = await Promise.all(ships.map(ship => childNodeFromSeed({
    seed: ownerSeed,
    type: 'spawn',
    revision: _revisions.spawn,
    ship: ship,
    password: password,
  })))

  const networkSeeds = await Promise.all(ships.map(ship => childSeedFromSeed({
    seed: bufferFrom(managementNode.seed),
    type: 'network',
    revision: _revisions.network,
    ship: ship,
    password: password,
  })))

  const networkNodes = await Promise.all(networkSeeds.map((seed, index) => ({
    seed: buf2hex(seed),
    keys: urbitKeysFromSeed(bufferFrom(seed), bufferFrom(defaultTo(password, ''))),
    meta: {
      type: 'network',
      revision: _revisions.network,
      ship: ships[index],
    }
  })))

  const wallet = {
    owner: ownershipNode,
    delegate: delegateNode,
    manage: managementNode,
    network: networkNodes,
    transfer: transferNodes,
    spawn: spawnNodes,
  }

  return wallet
}

export {
  argon2u,
  fullWalletFromTicket,
  fullWalletFromSeed,
  childNodeFromSeed,
  childSeedFromSeed,
  walletFromSeed,
  urbitKeysFromSeed,
}
