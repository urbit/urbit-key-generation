# urbit-key-generation

[![Build Status](https://secure.travis-ci.org/urbit/urbit-key-generation.png)](http://travis-ci.org/urbit/urbit-key-generation)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm](https://img.shields.io/npm/v/urbit-key-generation.svg)](https://www.npmjs.com/package/urbit-key-generation)

Key derivation and HD wallet generation functions for Urbit.

## Install

Grab it from npm like so:

```
npm install urbit-key-generation
```

To include in your node project, use:

``` javascript
const kg = require('urbit-key-generation')
```

To use in the browser, you can use e.g. [rollup][roll] and the
[rollup-plugin-node-resolve][rpnr] plugin, and specify the following in your
`rollup.config.js` or similar:

``` javascript
plugins: [
  ..,
  resolve({
    browser: true,
  }),
  ..
]
```

## Usage

You will probably be interested in the `generateWallet` function, which
generates a HD wallet for Urbit keys.  It expects an object argument containing
the following properties:

* `ticket`, a 64, 128, or 384-bit `@q` master ticket (you can use e.g. the
  appropriate `patq` functions from [urbit-ob][urbo] to create these from
  decimal or hex strings).
* `ship`, an Urbit ship number between 0 and 2^32 - 1.
* `passphrase`, an optional passphrase used to salt seeds derived from BIP39
  mnemonics.
* `revision`, an optional number used to salt network seeds derived from a
  management seed.  Defaults to `0`.
* `boot`, an optional flag that indicates whether or not to generate Urbit
  network keys for the provided ship.  Defaults to `false`.

`generateWallet` returns a Promise, so you can deal with it as follows, for
example:

``` javascript
let config = {
  ticket: '~marbud-tidsev-litsut-hidfep',
  ship: 65012,
  boot: true
}

let wallet = await generateWallet(config)
```

This library also contains functionality for generating Arvo keyfiles, via
`generateKeyfile`, as well as web UI login codes (`+code` in :dojo), via
`generateCode`.

## Security

Tlon runs a [bug bounty program][bugs].  If you believe you've discovered a
vulnerability anywhere in this implementation, you can disclose it privately to
[security@tlon.io][sect].

## Dev

Before making a PR, you should create an updated browser bundle (generated via
`npm run-script build`).

You can run the test suite with a simple `npm test`.

[urbo]: https://www.npmjs.com/package/urbit-ob
[roll]: https://rollupjs.org/guide/en
[rpnr]: https://github.com/rollup/rollup-plugin-node-resolve
[bugs]: https://urbit.org/bounties/
[sect]: mailto:security@tlon.io
