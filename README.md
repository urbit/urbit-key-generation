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

Most of the functions are asynchronous, so you'll have to deal with their `Promises`.

### `fullWalletFromTicket()` (async)

Derive all keys from the ticket.

**Arguments:**
- `ticket`: ticket bytes as hex-encoded `string` or `Uint8Array` or `Buffer`, at least 16 bytes,
- `seedSize`: desired size of the generated seeds in bytes,
- `ships`: array of ship-numbers to generate keys for,
- `password`: optional password to use during derivation,
- `revisions`: optional revision per key purpose (transfer, spawn, delegate, manage, network), defaults to all-zero
- `boot`: optional boolean flag specifying whether to boot ships or not

**Returns:**
```
{ ticket: ticket as hex,
  owner: { seed: "hexstring", keys: wallet },
  manage: node,
  delegate: node,
  transfer: array of nodes (to match ships argument),
  spawn: array of nodes (to match ships argument),
  network: array of nodes (to match ships argument) }
```

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

```js
import { fullWalletFromTicket } from 'urbit-keygen'

fullWalletFromTicket({
  ticket: Buffer.from('master ticket bytes'),
  ships: [1, 2, 3],
  password: 'password123', // Example. Do not use.
  revisions: { manage: 1 }
}).then(res => { console.log(JSON.stringify(res, null, 2)); })
  .catch(e => console.error(e))

// Resulting wallet
{
  "ticket": "6d6173746572207469636b6574206279746573",
  "owner": {
    "keys": {
      "public": "02991b351c5559b68042849dd207929852e73b3469f540e87576e343728b31dda5",
      "private": "e2beb8e06c1aef68ead1d55790ea806736e684d7738df17e6951dd7a86c4e339",
      "chain": "d7a52a774c16b92291d05dc1c0b12bbe0498c73cefc4c5f64d36ee7c62c39190"
    },
    "seed": "86726b801683d40cb7f1d9c5e3005e0f2c6fc6ab549b65c83866b009330d184d"
  },
  "voting": {
    "meta": {
      "type": "voting",
      "revision": 0,
      "ship": null
    },
    "seed": "5a2ceb6aafe8d36c78c1725629a15e24edfa97df8c06df011a60552bace5dfb5",
    "keys": {
      "public": "0224714b32b7739d6eef365651490e42c30df4b138e30576021fee9ec5a8543003",
      "private": "72e10503e650d4f1d6899e6e3e6c3d54fbf931f860a031516e246b63a5c7d810",
      "chain": "3413cc8249515ee23bb7ce1a3ea2e9b22d43d657867d519ffcb93d14d0d7d1de"
    }
  },
  "manage": {
    "meta": {
      "type": "manage",
      "revision": 1,
      "ship": null
    },
    "seed": "cb54e36054cfa78794b3f2aa19c45b46f54175030736ede85b6c525a767495ae",
    "keys": {
      "public": "0277214b3819c22e1c9dc07059c0b2b35fc219bbe5ede51e03d901268863191b73",
      "private": "8ea3d56bff86e279eed52df71128e386bdbee9551df3cd9b55bc9b692b02f22f",
      "chain": "79679117ff8f4acdff88ce2a37fcea8cbb4669137c9919c535b3cd83bd8209a6"
    }
  },
  "network": [],
  "transfer": [
    {
      "meta": {
        "type": "transfer",
        "revision": 0,
        "ship": 1
      },
      "seed": "661e4777b49102c104550908e63ab1152611b9b4d91dd99756b070a90b86dce5",
      "keys": {
        "public": "03300cf2c00cae5747fa99985e03abdac38b67787092fc93a361712d11878b71b0",
        "private": "15b05a5e91da5a2d22f363ccdf48cbfb501dde1c91a79d48fb4386659a7ae43d",
        "chain": "e492463cf9e2c323451db01541b7893b5062f36758223a61f1b41ea65cea323d"
      }
    },
    {
      "meta": {
        "type": "transfer",
        "revision": 0,
        "ship": 2
      },
      "seed": "ce59af930bbd2d7f4634a202c8d5043daa7ef83f3dad4b10acc5382aad76d606",
      "keys": {
        "public": "03449ad3c2b4ba416d788376110f90b589fbe9a191e76adc24f316c25d10e5dc87",
        "private": "6a1b516881c56f5101e4c3a5c98aff2ed4fcd1d7110b5fef8b42b6e53b0e2612",
        "chain": "29a0396c1b05ce73af8d8e2c5334f16d27efb5630b9ef67ce0d4f61b2fcd14f5"
      }
    },
    {
      "meta": {
        "type": "transfer",
        "revision": 0,
        "ship": 3
      },
      "seed": "eba0a8799e7939fd209a2eff1d1778d147906f89896ad1ceb667c84828aa5cb8",
      "keys": {
        "public": "022447f4ee0e2de1ed4a4207a71bb9e8f3dc304911ab09ba92b4f79b4812c1050a",
        "private": "83308dae8c2d812465189e716c004607bc03a795b63caa5918335ed63f74913b",
        "chain": "fd51758fe3338c3b4719c1b713ddf4361986c972ec1bb892b25dc80fa9f5860a"
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
      "seed": "fa39fb278a33bb3b1868590d87f7b1191bb230ab0d8304b99697e8878a2c61f0",
      "keys": {
        "public": "02115bda49ec0dd76bfdee88aacfe45901644726ddc23124b2b63b079279a150a4",
        "private": "40588e2053138477699ea40c92330097e417e4a1965b9e6c4195b786516f291c",
        "chain": "9b37ed6715be47ba46c2823f2a4919da505c906dd501cbca07fbe24d34c659aa"
      }
    },
    {
      "meta": {
        "type": "spawn",
        "revision": 0,
        "ship": 2
      },
      "seed": "18219d330fffd7d59d20182181179daa20af9e71058686835425bcbce52963ed",
      "keys": {
        "public": "02c3ed086fd552255e33a4880a4c15f4a1e748eed3a533ae563b04c6343d37dd2a",
        "private": "424c0a0e728cfe2c9c13ac80676c1b8d8ec1540d58c2df13be1275d86c3010c1",
        "chain": "774ef5a80271087dbd7d2affd13611fbfa1b04ee4cbd35d3ad2a1448b2f596b4"
      }
    },
    {
      "meta": {
        "type": "spawn",
        "revision": 0,
        "ship": 3
      },
      "seed": "79724f6758c7d0e41f15d4547797b55ce7ed695010c5c3d2df8e0aa0c3d70d6b",
      "keys": {
        "public": "035f2cb446a2a303df24b659ee4f194afe6aaed99f86a80e04a1c267c1720f2b88",
        "private": "3654a03aeafbd4367b78da0f65dbe1d2c1886f4654a10716e1169c1618596b73",
        "chain": "6e230eccb06fc9206e444063dc904277ca43905936ac59ed3d2af2e649852e36"
      }
    }
  ]
}
```
