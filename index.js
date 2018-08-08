const crypto = require('isomorphic-webcrypto')
const bip32 = require('bip32');
const nacl = require('tweetnacl');
const argon2 = require('argon2-wasm');
const drbg = require('hmac-drbg');
const hash = require('hash.js');

//TODO figure out which format to work with externally: Buffer, Uint8Array, BufferArray?
//TODO generate arbitrary-length seeds
//TODO maybe variable for storing password so you don't have to pass it in?

function buf2hex(buffer) // ArrayBuffer
{
  return Array.prototype.map.call(
    new Uint8Array(buffer),
    x => ('00' + x.toString(16)).slice(-2)
  ).join('');
}

//TODO isn't user generated entropy actual entropy already? what does
//     deterministically deriving new entropy from that gain us?
function generateEntropy(entropySeed, entropySize)
{
  const d = new drbg({
    hash:    hash.sha256,
    entropy: entropySeed,
    nonce:   'todo',
    pers:    null
  });
  return d.generate(entropySize, 'arr'); // 'hex', or anything else for array
}

async function argon2u(entropy, ticketSize)
{
  return await argon2({
    pass:     entropy, // string or Uint8Array
    salt:     'urbitkeygen',
    type:     10, // argon2.ArgonType.Argon2u,
    hashLen:  +(ticketSize),
    distPath: 'node_modules/argon2-wasm/dist'
  });
}

function getChildSeed(seed, type, revision, ship, password) // Uint8Array, string, ...
{
  let salt = type+'-'+revision;
  if (typeof ship === 'number') salt = salt+'-'+ship;
  return crypto.subtle.digest(
    {name: 'SHA-512'},
    Buffer.concat([
      Buffer.from(seed),
      Buffer.from(salt),
      Buffer.from(password || '')
    ])
  );
}

function walletFromSeed(seed, password)
{
  //TODO doesn't support seeds of lengths < 128 bits and > 512
  let wallet = bip32.fromSeed(Buffer.concat([
    Buffer.from(seed),
    Buffer.from(password || '')
  ]));
  return {
    public:  buf2hex(wallet.publicKey),
    private: buf2hex(wallet.privateKey),
    chain:   buf2hex(wallet.chainCode)
  }
}

async function deriveWallet(startSeed, path)
{
  let childSeed = startSeed;
  for(i = 0; i < path.length; i++)
  {
    let node = path[i];
    childSeed = await getChildSeed(childSeed, node.type, node.revision, node.ship);
  }
  return walletFromSeed(Buffer.from(ownerSeed));
}

// matches ++pit:nu:crub:crypto
function urbitKeysFromSeed(seed, size, password)
{
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
      public: buf2hex(crypt.publicKey.reverse())
    },
    auth: {
      private: buf2hex(a.reverse()),
      public: buf2hex(auth.publicKey.reverse())
    }
  }
}

async function fullWalletFromEntropy(entropy, ships, password)
{
  let ownerSeed = (await argon2u(entropy, 16)).hash; // Uint8Array
  return fullWalletFromSeed(ownerSeed, ships, password);
}

async function fullWalletFromSeed(ownerSeed, ships, password)
{
  let result = {};

  result.owner = walletFromSeed(Buffer.from(ownerSeed), password);

  let deletageSeed =
    await getChildSeed(ownerSeed, 'delegate', 0, null, password);
  result.delegate = walletFromSeed(deletageSeed, password);

  let manageSeed =
    await getChildSeed(ownerSeed, 'manage', 0, null, password);
  result.manager = walletFromSeed(manageSeed, password);

  result.transferKeys = [];
  result.spawnKeys    = [];
  result.networkKeys  = [];
  for (i = 0; i < ships.length; i++)
  {
    let ship = ships[i];

    let transferSeed =
      await getChildSeed(ownerSeed, 'transfer', 0, ship, password);
    result.transferKeys[i] = walletFromSeed(transferSeed, password);

    let spawnSeed =
      await getChildSeed(transferSeed, 'spawn', 0, ship, password);
    result.spawnKeys[i]    = walletFromSeed(spawnSeed, password);

    let urbitSeed =
      await getChildSeed(manageSeed, 'network', 0, ship, password);
    result.networkKeys[i] = urbitKeysFromSeed(Buffer.from(urbitSeed), password);
  }

  return result;
}

module.exports = {
  argon2u,
  fullWalletFromEntropy,
  fullWalletFromSeed
};
