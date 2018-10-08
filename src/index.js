const crypto = require('isomorphic-webcrypto');
const argon2 = require('argon2-wasm');
const nacl = require('tweetnacl');
const bip32 = require('bip32');
const lodash = require('lodash');
const ob = require('ob-js');

/**
 * Check if a ship is a galaxy.
 * @param  {integer}  ship
 * @return  {bool}  true if galaxy, false otherwise
 */
const isGalaxy = ship => Number.isInteger(ship) && ship >= 0 && ship < 256;



/**
 * Split a string at the provided index, returning both chunks.
 * @param  {integer}  index the index to split at
 * @param  {string}  string a string
 * @return  {array of strings}  the split string
 */
const splitAt = (index, str) => [str.slice(0, index), str.slice(index)];



/**
 * if any is undefined, return d. Otherwise return any
 * @param  {any} a value to check if defined
 * @param  {any} d   value to swap in if undefined.
 * @return {any}  either a or d
 */
const defaultTo = (a, d) => isUndefined(a) ? d : a;



/**
 * get a value from an object with a key. If no value is found or object is
 * undefined, return d
 * @param  {object} o The object to pull from.
 * @param  {string} k The key to use.
 * @param  {any} d The default value to swap in eith o or k is undefined.
 * @return {any}
 */
const get = (o, k, d) => {
  if (isUndefined(o)) return d;
  const r = o[k];
  return isUndefined(r) ? d : r;
};



/**
 * returns true if a is undefined, false if not.
 * @param  {any}  a the value to check
 * @return {Boolean}
 */
const isUndefined = a => typeof a === 'undefined';



/**
 * returns true if a is a number, false if not.
 * @param  {any}  any the value to check
 * @return {Boolean}
 */
const isNumber = a => typeof a === 'number' && isFinite(a);



/**
 * Converts a buffer to hexidecimal string
 * @param  {Buffer} buffer
 * @return {string}
 */
const buf2hex = buffer => {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};



/**
 * Converts a hexidecimal string to a buffer.
 * @param  {string} a hex-encoded string
 * @return {Buffer}
 */
const hex2buf = hex => {
  return Buffer.from(hex, 'hex');
};



/**
 * executes SHA-512 on any size input
 * @param  {Array, ArrayBuffer, Buffer, string} args any number of arguments
 * @return {Promise => ArrayBuffer} Promise that resolves to arrayBuffer
 */
const hash = async (...args) => {
  // map args into buffers and concat into one buffer
  const buffer = Buffer.concat(args.map(a => Buffer.from(a)));
  // generate a SHA-512 hash from input buffer
  return crypto.subtle.digest({ name: 'SHA-512' }, buffer);
};



/**
 * Runs argon2wasm to return a seed of desired bytes
 * @param  {Uint8Array, Buffer, string} entropy ticket bytes as string or
 * Uint8Array or Buffer, at least 16 bytes
 * @param  {int} seedSize desired size of the generated seeds in bytes
 * @return {Promise => ArrayBuffer} Promise that resolves to arrayBuffer
 */
const argon2u = (entropy, seedSize) => argon2.hash({
  pass: entropy, // string or Uint8Array
  salt: 'urbitkeygen',
  type: argon2.types.Argon2u,
  hashLen: seedSize,
  // distPath: 'node_modules/argon2-wasm/dist',
  parallelism: 4,
  mem: 512000,
  time: 1,
});



/**
 * Derive a new seed from a seed. Uses a config with the following entries:
 * @param  {Buffer}   seed seed to derive from.
 * @param  {string}   type the type of the seed we want to derive:
 * ("transfer", "spawn", "voting", "manage", "network").
 * @param  {object}   revision the revision number of the seed we want to derive.
 * @param  {integer}  ship  optional ship number we want to derive the seed for.
 * @param  {string}   password  optional password to salt the seed with before
 * deriving.
 * @return {Promise => Buffer} a new seed
 */
const childSeedFromSeed = async config => {
  const { seed, type, revision, ship, password } = config;

  const salt = isNumber(ship)
    ? `${type}-${revision}-${ship}`
    : `${type}-${revision}`;

  const childSeed = await hash(seed, salt, defaultTo(password, ''));

  return childSeed.slice(0, seed.byteLength || seed.length);
};



/**
 * Derive a new node from a seed. Uses a config with the following entries:
 * @param  {Buffer}   seed seed to derive from.
 * @param  {string}   type the type of the seed we want to derive:
 * ("transfer", "spawn", "voting", "manage", "network").
 * @param  {integer}  revision the revision number of the seed we want to derive.
 * @param  {integer}  ship  optional ship number we want to derive the seed for.
 * @param  {string}   password  optional password to salt the seed with before
 * deriving.
 * @return {Promise => Object} a new node
 */
const childNodeFromSeed = async config => {
  const { seed, type, revision, ship, password } = config;
  const childSeed = await childSeedFromSeed({seed, type, revision, ship, password});
  return {
    meta: {
      type,
      revision: defaultTo(revision, 0),
      ship: !isUndefined(ship)
        ? ship
        : null
    },
    seed: buf2hex(childSeed),
    keys: await walletFromSeed(childSeed, password),
  };
};



/**
 * Derive a BIP32 master node from a seed.
 * @param  {string, Buffer}  seed     seed to derive from.
 * @param  {string}          password optional password to salt the seed with before
 * deriving.
 * @return {Promise => Object} a wallet derived according to BIP32 from the
 *  SHA-512 hash of the seed+password.
 */
const walletFromSeed = async (seed, password) => {
  // we hash the seed with SHA-512 before doing BIP32 wallet generation,
  // because BIP32 doesn't support seeds of bit-lengths < 128 or > 512.
  const seedHash = await hash(seed, defaultTo(password, ''));
  const { publicKey, privateKey, chainCode } = bip32.fromSeed(Buffer.from(seedHash));
  return {
    public: buf2hex(publicKey),
    private: buf2hex(privateKey),
    chain: buf2hex(chainCode),
  };
};



/**
 * Wraps nacl.lowlvel.crypto_hash
 * @param  {Uint8Array} seed
 * @return {Array}
 */
const naclHash = seed => {
  let newHash = []
  nacl.lowlevel.crypto_hash(newHash, seed.reverse(), seed.length)
  return newHash
}



/**
 * Derive Urbit network keypairs from a seed. Matches ++pit:nu:crub:crypto
 * @param  {Buffer} seed     seed to derive from
 * @param  {Buffer} password optional password to salt the seed before deriving
 * @return {object} urbitKeys, derived according to ++pit:nu:crub:crypto.
 */
const urbitKeysFromSeed = (seed, password) => {
  const h = naclHash(Buffer.concat([seed, password]));

  const c = h.slice(32);
  const a = h.slice(0, 32);

  const crypt = nacl.sign.keyPair.fromSeed(Buffer.from(c));
  const auth = nacl.sign.keyPair.fromSeed(Buffer.from(a));

  return {
    crypt: {
      private: buf2hex(c.reverse()),
      public: buf2hex(crypt.publicKey.reverse()),
    },
    auth: {
      private: buf2hex(a.reverse()),
      public: buf2hex(auth.publicKey.reverse()),
    }
  };
};



/**
 * Reduce a collection of arrays by recursive applications of bytewise XOR.
 * @param  {Array of Array of integers}  arrays an array of arrays
 * @return {Array} the resulting array
 */
const reduceByXor = (arrays) => {
  return arrays.reduce((acc, arr) =>
    lodash.zipWith(acc, arr, (x, y) => x ^ y));
}



/**
 * Encode a hex string as three shards, such that any two shards can be
 * combined to recover it.
 * @param  {string}  string hex-encoded string
 * @return {Array of strings} resulting shards
 */
const shardHex = hex => {
  const buffer = hex2buf(hex);
  const sharded = shardBuffer(buffer);
  return sharded.map(pair =>
    lodash.reduce(pair, (acc, arr) =>
      acc + buf2hex(Buffer.from(arr)), ''))
}



/**
 * Encode a @q-encoded string as three shards, such that any two shards can be
 * combined to recover it.
 * @param  {string}  string @q-encoded string
 * @return {Array of strings} resulting shards
 */
const shardPatq = patq => {
  const hexed = shardHex(ob.patq2hex(patq))
  return hexed.map(ob.hex2patq)
}



/**
 * Produce three shards from a buffer such that any two of them can be used to
 * reconstruct it.
 * @param  {Buffer}  buffer arbitrary buffer
 * @return {Array of Array of integers} sharded buffer
 */
const shardBuffer = buffer => {
  const r1 = crypto.getRandomValues(new Uint8Array(buffer.length));
  const r2 = crypto.getRandomValues(new Uint8Array(buffer.length));

  const k  = Array.from(buffer);
  const k1 = Array.from(r1);
  const k2 = Array.from(r2);

  const k0 = reduceByXor([k, k1, k2]);

  const shard0 = [k0, k1];
  const shard1 = [k0, k2];
  const shard2 = [k1, k2];

  return [shard0, shard1, shard2];
};



/**
 * Combine pieces of a sharded buffer together to recover the original buffer.
 * @param  {Array of Array of integers}  shards a collection of shards
 * @return {Buffer} the unsharded buffer
 */
const combineBuffer = shards => {
  const flattened = lodash.flatten(shards);
  const uniques = lodash.uniqWith(flattened, lodash.isEqual);
  const reduced = reduceByXor(uniques);
  return Buffer.from(reduced);
}



/**
 * Combine hex-encoded shards together to reconstruct a secret.
 * @param  {Array of Array of strings}  shards a collection of hex-encoded
 *  shards
 * @return {string} the reconstructed secret
 */
const combineHex = shards => {
  const splat = shards.map(shard =>
    splitAt(shard.length / 2, shard));
  const buffers = splat.map(pair =>
    pair.map(buf => Array.from(hex2buf(buf))));
  const combined = combineBuffer(buffers);
  return buf2hex(combined);
}



/**
 * Combine @q-encoded shards together to reconstruct a secret.
 * @param  {Array of Array of strings}  shards a collection of @q-encoded
 *  shards
 * @return {string} the reconstructed secret
 */
const combinePatq = shards => {
  const hexed = shards.map(shard => ob.patq2hex(shard))
  const combined = combineHex(hexed)
  return ob.hex2patq(combined)
}



/**
 * Convert a full wallet into a sharded wallet.  Transforms the owner's seed
 * into a number of shards, of which only a subset are required in order to
 * reconstruct the original.
 *
 * @param  {object}  wallet full HD wallet
 * @return  {object} an object representing a sharded full HD wallet
 */
const shardWallet = wallet => {
  const walletCopy = lodash.cloneDeep(wallet);
  const sharded = shardPatq(walletCopy.ticket)
  walletCopy.ticket = sharded;
  return walletCopy;
}



/**
 * Derive all keys from the ticket.
 * @param  {string, Uint8Array, Buffer}  ticket ticket, at least 16 bytes.
 * @param  {integer}  seedSize desired size of the generated seeds in bytes.
 * @param  {Array of integers}  ships array of ship-numbers to generate keys for.
 * @param  {string}  password optional password to use during derivation.
 * @param  {object}  revisions optional revision per key purpose:
 * (transfer, spawn, voting, manage, network), defaults to all-zero
 * @param  {Boolean}  boot optional generate networking keys for this wallet
 * @return {Promise => object} an object representing a full HD wallet.
 */
const fullWalletFromTicket = async config => {
  const { ticket, seedSize, ships, password, revisions, boot } = config;

  const seed = await argon2u(ticket, seedSize);
  const ownerSeed = Buffer.from(seed.hash)

  // Normalize revisions object
  const _revisions = {
    transfer: get(revisions, 'transfer', 0),
    spawn: get(revisions, 'spawn', 0),
    voting: get(revisions, 'voting', 0),
    manage: get(revisions, 'manage', 0),
    network: get(revisions, 'network', 0),
  };

  const ownershipNode = {
    keys: await walletFromSeed(ownerSeed, password),
    seed: buf2hex(ownerSeed),
  }

  const manageNodes = await Promise.all(ships.map(ship =>
     childNodeFromSeed({
       seed: ownerSeed,
       type: 'manage',
       revision: _revisions.manage,
       ship: ship,
       password: password,
    })));

  const manageSeeds = lodash.mapValues(lodash.keyBy(manageNodes, 'meta.ship'), 'seed');

  const votingNodes = await Promise.all(ships.filter(ship => isGalaxy(ship)).map(ship => childNodeFromSeed({
      seed: ownerSeed,
      type: 'voting',
      revision: _revisions.voting,
      ship: ship,
      password: password,
    })));

  const transferNodes = await Promise.all(ships.map(ship => childNodeFromSeed({
    seed: ownerSeed,
    type: 'transfer',
    revision: _revisions.transfer,
    ship: ship,
    password: password,
  })));

  const spawnNodes = await Promise.all(ships.map(ship => childNodeFromSeed({
    seed: ownerSeed,
    type: 'spawn',
    revision: _revisions.spawn,
    ship: ship,
    password: password,
  })));


  let networkSeeds = [];
  let networkNodes = [];

  if (boot === true) {

    networkSeeds = await Promise.all(ships.map(ship => childSeedFromSeed({
      seed: hex2buf(manageSeeds[ship]),
      type: 'network',
      revision: _revisions.network,
      ship: ship,
      password: password,
    })));

    networkNodes = await Promise.all(networkSeeds.map((seed, index) => ({
      seed: buf2hex(seed),
      keys: urbitKeysFromSeed(Buffer.from(seed), Buffer.from(defaultTo(password, ''))),
      meta: {
        type: 'network',
        revision: _revisions.network,
        ship: ships[index],
      }
    })));
  };

  const displayTicket = ob.hex2patq(ticket)

  const wallet = {
    ticket: displayTicket,
    owner: ownershipNode,
    manage: manageNodes,
    voting: votingNodes,
    network: networkNodes,
    transfer: transferNodes,
    spawn: spawnNodes,
  };

  return wallet;
}

const _buf2hex = buf2hex;
const _hex2buf = hex2buf;
const _hash = hash;
const _argon2 = argon2;
const _defaultTo = defaultTo;
const _get = get;
const _shardBuffer = shardBuffer;
const _combineBuffer = combineBuffer;
const _shardHex = shardHex;
const _combineHex = combineHex;
const _shardPatq = shardPatq;
const _combinePatq = combinePatq;

module.exports = {
  argon2u,
  fullWalletFromTicket,
  childNodeFromSeed,
  childSeedFromSeed,
  walletFromSeed,
  urbitKeysFromSeed,
  shardWallet,
  _buf2hex,
  _hex2buf,
  _hash,
  _argon2,
  _defaultTo,
  _get,
  _shardBuffer,
  _combineBuffer,
  _shardHex,
  _combineHex,
  _shardPatq,
  _combinePatq
}
