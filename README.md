Key generation and derivation for Urbit.

## Interface

First, some definitions, for easier outlining of the data returned by this library.

- **wallet:** represents a BIP32 master node,  
  ```
  { public: "hexstring", private: "hexstring", chain: "hexstring" }
  ```
- **urbitKeys:** represent Urbit network keys,  
  ```
  { crypt: { public: "hexstring", private: "hexstring" },  
    auth: { public: "hexstring", private: "hexstring" } }
  ```
- **node:** secrets and meta-data,  
  ```
  { seed: "hexstring",
    keys: wallet (or urbitKeys for "network" type nodes),
    meta: { type: "string", revision: int, ship: optional int } }
  ```

Most of the functions are asynchronous, so you'll have to deal with their `Promise`s.

### `fullWalletFromTicket()` (async)

Derive all keys from the ticket.

**Arguments:**
- `ticket`: ticket bytes as `string` or `Uint8Array` or `Buffer`, at least 16 bytes,
- `seedSize`: desired size of the generated seeds in bytes,
- `ships`: array of ship-numbers to generate keys for,
- `password`: optional password to use during derivation,
- `revisions`: optional revision per key purpose (transfer, spawn, delegate, manage, network), defaults to all-zero

**Returns:**  
```
{ owner: { seed: "hexstring", keys: wallet },
  manage: node,
  delegate: node,
  transfer: array of nodes (to match ships argument),
  spawn: array of nodes (to match ships argument),
  network: array of nodes (to match ships argument) }
```

### `fullWalletFromSeed()` (async)

Derive all keys from the ownership seed. All generated seed match the ownership seed in size.

**Arguments:**  
- `ownerSeed`: ownership seed as `Buffer`,
- `ships`: array of ship-numbers to generate keys for,
- `password`: optional password to use during derivation,
- `revisions`: optional revision per key purpose (transfer, spawn, delegate, manage, network), defaults to all-zero

**Returns:**  
See `fullWalletFromTicket()`.

### `childNodeFromSeed()` (async)

Derive a wallet node from the given seed.

**Arguments:**  
- `seed`: seed to derive from as `Buffer`,
- `type`: the type of the seed we want to derive ("transfer", "spawn", "delegate", "manage", "network"),
- `revision`: the revision number of the seed we want to derive,
- `ship`: optional ship number we want to derive the seed for,
- `password`: optional password to salt the seed with before deriving

**Returns:**  
`node`, with its `meta` matching the arguments.

### `childSeedFromSeed()` (async)

Derive a new seed from a seed.

**Arguments:**  
See `childNodeFromSeed()`.

**Returns:**  
`Buffer`

### `walletFromSeed()` (async)

Derive a BIP32 master node from a seed.

**Arguments:**  
- `seed`: seed to derive from as `Buffer`,
- `password`: optional password to salt the seed with before deriving

**Returns:**  
`wallet`, derived according to BIP32 from the SHA-512 hash of the seed+password.

### `urbitKeysFromSeed()`

Derive Urbit network keypairs from a seed.

**Arguments:**  
- `seed`: seed to derive from as `Buffer`,
- `password`: optional password to salt the seed with before deriving

**Returns:**  
`urbitKeys`, derived according to `++pit:nu:crub:crypto`.

## Usage

```
npm install
```

```
> kg = require('.')
> kg.fullWalletFromTicket('master ticket bytes', 16, [1], 'password', {manage: 1}).then(res => { console.log(JSON.stringify(res, null, 2)); }).catch(console.error)
Promise { ... }
{
  "owner": {
    "seed": "5c777c50036aa148c8140d9ad87c4031",
    "keys": {
      "public": "0215130350ff9df9bcaf4b8d71647ba7caddf7927aab2cd401c98fe96ac4726656",
      "private": "900825e7e673b2659b2b2e6d7de726b76d1b479eb82d9f95d735391a056013dc",
      "chain": "b5660ba881252f95854ce270503c1e628926635657b4037896a8e9ecedcdb464"
    }
  },
  "manage": {
    "meta": {
      "type": "manage",
      "revision": 1
    },
    "seed": "8f240880c61fa82c1eba8fb2c2835c7f",
    "keys": {
      "public": "02d916b11daf333c88295d2283dc3902886b33ace6afb272556da73464437e7b9d",
      "private": "20a57daf889dac75d9cacf53d4171fef2641d3a36aea82202f1a293a4ce17866",
      "chain": "e67085062c484f96b71acfc775b52c4826f417d823b52a081091b3bbc7e05f0f"
    }
  },
  "transfer": [
    {
      "meta": {
        "type": "transfer",
        "revision": 0,
        "ship": 1
      },
      "seed": "04fc56fd7185fe00af568a3242dc7dab",
      "keys": {
        "public": "029718af0c68e9e694efce43b9400b8159ab08febc2273891d58ee5661cb0d726b",
        "private": "0203652ad0a0d9031d3791573c24bc1850b50d4b2e25d323fa74ddcd68a66631",
        "chain": "868083aba5f72c763da3555c1a1af3f07c2edbd23666dc5f19497458829af1a8"
      }
    }
  ],
  "spawn": [
    {
      "meta": {
        "type": "spawn",
        "revision": 0,
        "ship": 1
      },
      "seed": "fca2c974fc30c64596f1c2248d99106b",
      "keys": {
        "public": "038321f6b6ab98049736837ce2a09926ab5e56cb622e771a8fefb17d4280a7001a",
        "private": "560f137b15bb8be49b1de02dd68fa74d1efe31abe393d671eba580234a82e9e2",
        "chain": "44c24d9351996dffc1d6949769842a444ccfb8362d3ad012cf05bcf598836bb3"
      }
    }
  ],
  "network": [
    {
      "meta": {
        "type": "network",
        "revision": 0,
        "ship": 1
      },
      "seed": "c6eb536c103bb9e8729fe252f57aee8d",
      "keys": {
        "crypt": {
          "private": "7794a31e5eca7060cf785b0b287637296b7b4b4ce4c3942aa577cbcb1b28aafa",
          "public": "8a273db7304a7d2dd7fc6fe1b6bc0899453a5d595559ff67d11d1f6cb16c8fe4"
        },
        "auth": {
          "private": "f2e747a9b11d1e5b5c52f2a2a5582f131d0d145b6d31f0d13b37162bbb1a3004",
          "public": "3c286854197814ebd829f443e1922fdfa5fb0a81b0c1d1416ae10670c1c2951b"
        }
      }
    }
  ],
  "delegate": {
    "meta": {
      "type": "delegate",
      "revision": 0,
      "ship": null
    },
    "seed": "45e6b825a703edd421397c65d8d631b8",
    "keys": {
      "public": "02b701910f31c80552db4adcb9dd59734fee00c98a92d4962027634b7181408e34",
      "private": "626e957bcdd1a385e0d44712dbb608c7649d367fbd34b49cd5d3b9fc14015e62",
      "chain": "7d4ec6125e022837d71761723339c9efc3a8c45b31923e9102c9ee76cdc72838"
    }
  }
}
```
