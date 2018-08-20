const {
  fullWalletFromTicket,
  fullWalletFromSeed,
  childNodeFromSeed,
  childSeedFromSeed,
  walletFromSeed,
  urbitKeysFromSeed,
  _buf2hex,
  _hash,
  _argon2u,
} = require('../index-g.js')

exports['test synchronous'] = assert => {

  const b = new Uint8Array([21, 31])
  assert.equal(_buf2hex(b), '151f', 'test buf2hex()')

}

exports['test async'] = (assert, done) => {

  // _argon2u('1', 8).then(r => {
  //   assert.notEqual(r, 'foo', 'test argon2u()')
  //   done()
  // })

}


if (module == require.main) require('test').run(exports);
