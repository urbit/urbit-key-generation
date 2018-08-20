const crypto = require('isomorphic-webcrypto');
const bip32 = require('bip32');
const nacl = require('tweetnacl');
const argon2 = require('argon2-wasm');

const buf2hex = buffer => {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

function hash() {
  // any number of arguments
  return crypto.subtle.digest(
    { name: 'SHA-512' },
    Buffer.concat(Array.from(arguments).map(Buffer.from))
  );
}

function argon2u(entropy, ticketSize) {
  return argon2({
    pass: entropy, // string or Uint8Array
    salt: 'urbitkeygen',
    type: 10, // argon2.ArgonType.Argon2u,
    hashLen: +ticketSize,
    distPath: 'node_modules/argon2-wasm/dist',
    parallelism: +4,
    mem: +512000,
    time: +1,
  });
}

async function childSeedFromSeed(
  seed,
  type,
  revision,
  ship,
  password // Uint8Array, string, ...
) {
  let salt = type + '-' + revision;
  if (typeof ship === 'number') salt = salt + '-' + ship;
  //TODO the Buffer.from is needed for ArrayBuffer seeds, but... why?
  //     we already to Buffer.from within hash()...
  return (await hash(Buffer.from(seed), salt, password || '')).slice(
    0,
    seed.length || seed.byteLength
  );
}

async function walletFromSeed(seed, password) {
  // we hash the seed with SHA-512 before doing BIP32 wallet generation,
  // because BIP32 doesn't support seeds of bit-lengths < 128 or > 512.
  let wallet = bip32.fromSeed(
    Buffer.from(
      //TODO why Buffer.from? also see childSeedFromSeed().
      await hash(Buffer.from(seed), password || '')
    )
  );
  return {
    public: buf2hex(wallet.publicKey),
    private: buf2hex(wallet.privateKey),
    chain: buf2hex(wallet.chainCode),
  };
}

// matches ++pit:nu:crub:crypto
function urbitKeysFromSeed(seed, password) {
  seed = Buffer.concat([seed, Buffer.from(password || '')]);
  let hash = [];
  nacl.lowlevel.crypto_hash(hash, seed.reverse(), seed.length);
  let c = hash.slice(32);
  let a = hash.slice(0, 32);
  let crypt = nacl.sign.keyPair.fromSeed(Buffer.from(c));
  let auth = nacl.sign.keyPair.fromSeed(Buffer.from(a));
  return {
    crypt: {
      private: buf2hex(c.reverse()),
      public: buf2hex(crypt.publicKey.reverse()),
    },
    auth: {
      private: buf2hex(a.reverse()),
      public: buf2hex(auth.publicKey.reverse()),
    },
  };
}

async function childNodeFromSeed(seed, type, revision, ship, password) {
  let result = {};
  revision = revision || 0;

  result.meta = { type: type, revision: revision };
  if (typeof ship !== 'undefined' && ship !== null) result.meta.ship = ship;
  let childSeed = await childSeedFromSeed(seed, type, revision, ship, password);
  result.seed = buf2hex(childSeed);
  result.keys = await walletFromSeed(childSeed, password);
  return result;
}

async function fullWalletFromTicket(ticket, seedSize, ships, password, revs) {
  let ownerSeed = Buffer.from((await argon2u(ticket, seedSize)).hash);
  return fullWalletFromSeed(ownerSeed, ships, password, revs);
}

async function fullWalletFromSeed(ownerSeed, ships, password, revisions) {
  let result = {};
  let seedSize = ownerSeed.length;
  revisions = revisions || {};
  revisions.transfer = revisions.transfer || 0;
  revisions.spawn = revisions.spawn || 0;
  revisions.delegate = revisions.delegate || 0;
  revisions.manage = revisions.manage || 0;
  revisions.network = revisions.network || 0;

  result.owner = {};
  result.owner.seed = buf2hex(ownerSeed);
  let ownerPromise = walletFromSeed(ownerSeed, password);

  let delegatePromise = childNodeFromSeed(
    ownerSeed,
    'delegate',
    revisions.delegate,
    null,
    password
  );

  let manageSeed = await childSeedFromSeed(
    ownerSeed,
    'manage',
    revisions.manage,
    null,
    password
  );
  result.manage = {};
  result.manage.meta = { type: 'manage', revision: revisions.manage };
  result.manage.seed = buf2hex(manageSeed);
  let managePromise = walletFromSeed(manageSeed, password);

  result.transfer = [];
  result.spawn = [];
  result.network = [];
  let transferPromises = [];
  let spawnPromises = [];
  let networkPromises = [];
  for (i = 0; i < ships.length; i++) {
    let ship = ships[i];

    transferPromises[i] = childNodeFromSeed(
      ownerSeed,
      'transfer',
      revisions.transfer,
      ship,
      password
    );

    spawnPromises[i] = childNodeFromSeed(
      ownerSeed,
      'spawn',
      revisions.spawn,
      ship,
      password
    );

    result.network[i] = {};
    result.network[i].meta = {
      type: 'network',
      revision: revisions.network,
      ship: ship,
    };
    networkPromises[i] = childSeedFromSeed(
      manageSeed,
      'network',
      revisions.network,
      ship,
      password
    );
  }

  result.owner.keys = await ownerPromise;
  result.delegate = await delegatePromise;
  result.manage.keys = await managePromise;

  for (i = 0; i < ships.length; i++) {
    result.transfer[i] = await transferPromises[i];
    result.spawn[i] = await spawnPromises[i];

    let networkSeed = await networkPromises[i];
    result.network[i].seed = buf2hex(networkSeed);
    result.network[i].keys = urbitKeysFromSeed(
      Buffer.from(networkSeed),
      password
    );
  }

  return result;
}

module.exports = {
  fullWalletFromTicket,
  fullWalletFromSeed,
  childNodeFromSeed,
  childSeedFromSeed,
  walletFromSeed,
  urbitKeysFromSeed,
};
