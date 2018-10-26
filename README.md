# urbit-keygen

[![Build Status](https://secure.travis-ci.org/urbit/keygen-js.png)](http://travis-ci.org/urbit/keygen-js)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Key derivation and HD wallet generation functions for Urbit.

## Usage

You will probably be interested in the `generateWallet` function, which
generates a HD wallet for Urbit keys.  It expects an object argument containing
the following properties:

* `ticket`, a 64, 128, or 384-bit `@q` master ticket (you can use e.g. the
  `hex2patq` function from [urbit-ob][urbo] to create these from hex strings).
* `ship`, an Urbit ship number between 0 and 2^32 - 1.
* `password`, an optional password used to salt seeds derived from BIP39
  mnemonics.
* `revision`, an optional number used to salt seeds derived from BIP39
  mnemonics.  Defaults to `0`.
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

## Including

To include in your node project, simply

``` javascript
const kg = require('urbit-keygen')
```

To use in the browser, you should use e.g. [rollup][roll] and the
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

## Dev

Before making a PR, remember to include an updated browser bundle (generated
via `npm run-script build`).  You can run the test suite with a simple `npm
test`.


[urbo]: https://www.npmjs.com/package/urbit-ob
[roll]: https://rollupjs.org/guide/en
[rpnr]: https://github.com/rollup/rollup-plugin-node-resolve

