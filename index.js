const crypto = require('isomorphic-webcrypto')
const bip32 = require('bip32');
const nacl = require('tweetnacl');
const argon2 = require('argon2-wasm');
const drbg = require('hmac-drbg');
const hash = require('hash.js');

//TODO figure out which format to work with externally: Buffer, Uint8Array, BufferArray?
//TODO lots of discussion about desired interface etc

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

function getChildSeed(seed, type, series, ship) // Uint8Array, string, ...
{
  return crypto.subtle.digest(
    {name: 'SHA-512'},
    Buffer.concat([
      Buffer.from(seed),
      Buffer.from(type+'-'+series+'-'+ship)
    ])
  );
}

function walletFromSeed(seed)
{
  let wallet = bip32.fromSeed(Buffer.from(seed));
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
    childSeed = await getChildSeed(childSeed, node.type, node.series, node.ship);
  }
  return walletFromSeed(Buffer.from(ownerSeed));
}

// matches ++pit:nu:crub:crypto
function urbitKeysFromSeed(seed, size)
{
  let hash = [];
  nacl.lowlevel.crypto_hash(hash, seed.reverse(), size);
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

async function generateSparseWallet(entropy, ships)
{
  let result = generateFullWallet(entropy, ships);
  let maxi = 0;
  for (i = 0; i < ships.length; i++)
  {
    if(ships[i] > ships[maxi]) maxi = i;
  }
  result = await result;
  result.manageKeys = [result.manageKeys[maxi]];
  return result;
}

async function generateFullWallet(entropy, ships)
{
  let result = {};

  let ownerSeed = (await argon2u(entropy, 16)).hash; // Uint8Array
  result.owner = walletFromSeed(Buffer.from(ownerSeed));

  result.transferKeys = [];
  result.spawnKeys    = [];
  result.manageKeys   = [];
  result.urbitKeys    = [];
  for (i = 0; i < ships.length; i++)
  {
    let ship = ships[i];

    let transferSeed = await getChildSeed(ownerSeed, 'transfer', 0, ship);
    result.transferKeys[i] = walletFromSeed(transferSeed);

    let spawnSeed    = await getChildSeed(transferSeed, 'spawn', 0, ship);
    result.spawnKeys[i]    = walletFromSeed(spawnSeed);

    let manageSeed   = await getChildSeed(transferSeed, 'manage', 0, ship);
    result.manageKeys[i]   = walletFromSeed(manageSeed);

    let urbitSeed    = await getChildSeed(manageSeed, 'urbit', 0, ship);
    let usb = Buffer.from(urbitSeed);
    result.urbitKeys[i] = urbitKeysFromSeed(usb, usb.length);
  }

  return result;
}

module.exports = {
  argon2u,
  generateSparseWallet,
  generateFullWallet
};
