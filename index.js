const crypto = require('isomorphic-webcrypto')
const bip32 = require('bip32');
const nacl = require('tweetnacl');
const argon2 = require('argon2-wasm');

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

function hash() // any number of arguments
{
  return crypto.subtle.digest(
    {name: 'SHA-512'},
    Buffer.concat(Array.from(arguments).map(Buffer.from))
  );
}

function argon2u(entropy, ticketSize)
{
  return argon2({
    pass:     entropy, // string or Uint8Array
    salt:     'urbitkeygen',
    type:     10, // argon2.ArgonType.Argon2u,
    hashLen:  +(ticketSize),
    distPath: 'node_modules/argon2-wasm/dist'
  });
}

async function getChildSeed(seed, seedSize, type, revision, ship, password) // Uint8Array, string, ...
{
  let salt = type+'-'+revision;
  if (typeof ship === 'number') salt = salt+'-'+ship;
  //TODO the Buffer.from is needed for ArrayBuffer seeds, but... why?
  //     we already to Buffer.from within hash()...
  return (await hash(Buffer.from(seed), salt, password || ''))
         .slice(0, seedSize);
}

async function walletFromSeed(seed, password)
{
  // we hash the seed with SHA-512 before doing BIP32 wallet generation,
  // because BIP32 doesn't support seeds of bit-lengths < 128 or > 512.
  let wallet = bip32.fromSeed(Buffer.from(
    //TODO why Buffer.from? also see getChildSeed().
    await hash(Buffer.from(seed), password || '')
  ));
  return {
    public:  buf2hex(wallet.publicKey),
    private: buf2hex(wallet.privateKey),
    chain:   buf2hex(wallet.chainCode)
  }
}

// matches ++pit:nu:crub:crypto
function urbitKeysFromSeed(seed, password)
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

async function fullWalletFromEntropy(entropy, seedSize, ships, password)
{
  let ownerSeed = Buffer.from((await argon2u(entropy, seedSize)).hash);
  return fullWalletFromSeed(ownerSeed, ships, password);
}

async function fullWalletFromSeed(ownerSeed, ships, password)
{
  let result = {};
  result.seeds = {};
  let seedSize = ownerSeed.length;

  result.seeds.owner = buf2hex(ownerSeed);
  let ownerPromise = walletFromSeed(ownerSeed, password);

  let delegateSeed =
    await getChildSeed(ownerSeed, seedSize, 'delegate', 0, null, password);
  result.seeds.delegate = buf2hex(delegateSeed);
  let delegatePromise = walletFromSeed(delegateSeed, password);

  let manageSeed =
    await getChildSeed(ownerSeed, seedSize, 'manage', 0, null, password);
  result.seeds.manage = buf2hex(manageSeed);
  let managePromise = walletFromSeed(manageSeed, password);

  result.seeds.transfer = [];
  result.seeds.spawn    = [];
  result.seeds.network  = [];
  let transferPromises  = [];
  let spawnPromises     = [];
  let networkPromises   = [];
  for (i = 0; i < ships.length; i++)
  {
    let ship = ships[i];

    let transferSeed =
      await getChildSeed(ownerSeed, seedSize, 'transfer', 0, ship, password);
    result.seeds.transfer[i] = buf2hex(transferSeed);
    transferPromises[i] = walletFromSeed(transferSeed, password);

    let spawnSeed =
      await getChildSeed(transferSeed, seedSize, 'spawn', 0, ship, password);
    result.seeds.spawn[i] = buf2hex(spawnSeed);
    spawnPromises[i] = walletFromSeed(spawnSeed, password);

    let networkSeed =
      await getChildSeed(manageSeed, seedSize, 'network', 0, ship, password);
    result.seeds.network[i] = buf2hex(networkSeed);
    networkPromises[i] = urbitKeysFromSeed(Buffer.from(networkSeed), password);
  }

  result.owner    = await ownerPromise;
  result.delegate = await delegatePromise;
  result.manager  = await managePromise;

  result.transferKeys = [];
  result.spawnKeys    = [];
  result.networkKeys  = [];
  for (i = 0; i < ships.length; i++)
  {
    result.transferKeys[i] = await transferPromises[i];
    result.spawnKeys[i]    = await spawnPromises[i];
    result.networkKeys[i]  = await networkPromises[i];
  }

  return result;
}

module.exports = {
  argon2u,
  fullWalletFromEntropy,
  fullWalletFromSeed
};
