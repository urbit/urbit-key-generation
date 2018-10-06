const expect =  require('chai').expect
const jsc = require('jsverify')
const _ = require('lodash')

const {
  _buf2hex,
  _hex2buf,
  _shard,
  _combine,
  _shardBuffer,
  _combineBuffer
  } = require('../src')

describe('sharding', () => {
  let hexString = jsc.string.smap(
    x => Buffer.from(x).toString('hex'),
    x => Buffer.from(x, 'hex').toString()
  )

  let buffer = jsc.string.smap(
    x => Buffer.from(x),
    x => x.toString
  )

  it('hex2buf and buf2hex are inverses', () => {
    let iso0 = jsc.forall(hexString, hex => _buf2hex(_hex2buf(hex)) === hex)
    let iso1 = jsc.forall(buffer, buf =>
      _.isEqual(_hex2buf(_buf2hex(buf)), buf))

    jsc.assert(iso0)
    jsc.assert(iso1)
  })

  it('combineBuffer . shardBuffer ~ id', () => {
    let rel = jsc.forall(buffer, buf =>
      _.isEqual(_combineBuffer(_shardBuffer(buf)), buf))

    jsc.assert(rel)
  })

  it('combine . shard ~ id', () => {
    let rel = jsc.forall(hexString, hex => _combine(_shard(hex)) === hex)

    jsc.assert(rel)
  })
})

