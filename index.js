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

function getChildSeed(seed, salt) // Uint8Array, string
{
  return crypto.subtle.digest(
    {name: 'SHA-512'},
    Buffer.concat([Buffer.from(seed), Buffer.from(salt)])
  );
}

function walletFromSeed(seed)
{
  return bip32.fromSeed(Buffer.from(seed));
}

function walletToData(wallet)
{
  return {
    public:  buf2hex(wallet.publicKey),
    private: buf2hex(wallet.privateKey),
    chain:   buf2hex(wallet.chainCode)
  }
}

async function generateFullWallet(ticket, transferKeys, spawnKeys, ships)
{
  let result = {};

  let ownerSeed = (await argon2u(ticket, 16)).hash; // Uint8Array
  result.owner = walletToData(walletFromSeed(Buffer.from(ownerSeed)));

  let transferSeed    = await getChildSeed(ownerSeed, 'transferseed'+0);
  let transferMaster  = walletFromSeed(Buffer.from(await transferSeed));
  result.transferKeys = [];
  for(i = 0; i < transferKeys; i++)
  {
    result.transferKeys[i] = walletToData(transferMaster.derive(i));
  }

  let spawnSeed    = await getChildSeed(transferSeed, 'spawnseed'+0);
  let spawnMaster  = walletFromSeed(Buffer.from(spawnSeed));
  result.spawnKeys = [];
  for(i = 0; i < spawnKeys; i++)
  {
    result.spawnKeys[i] = walletToData(spawnMaster.derive(i));
  }

  let manageSeed    = await getChildSeed(spawnSeed, 'manageseed'+0);
  let urbitSeed     = await getChildSeed(manageSeed, 'urbitseed'+0);
  let manageMaster  = walletFromSeed(Buffer.from(manageSeed));
  result.manageKeys = [];
  result.liveKeys   = [];
  urbitSeed;
  for(i = 0; i < ships; i++)
  {
    let liveSeed = getChildSeed(urbitSeed, 'liveseed'+i);
    result.manageKeys[i] = walletToData(manageMaster.derive(i));
    let auth = nacl.sign.keyPair.fromSeed(
      // the nacl function only accepts 32-byte seeds
      Buffer.from((await liveSeed).slice(0,32))
    );
    //TODO crypt should use curve25519, which is somehow different from ed25519
    let crypt = nacl.sign.keyPair.fromSeed(
      Buffer.from((await liveSeed).slice(0,32))
    );
    result.liveKeys[i] = {
      auth: {
        public:  buf2hex(auth.publicKey),
        private: buf2hex(auth.secretKey)
      },
      crypt:  {
        public:  buf2hex(crypt.publicKey),
        private: buf2hex(crypt.secretKey)
      }
    }
  }

  return result;
}

module.exports = {
  argon2u,
  generateFullWallet
};
