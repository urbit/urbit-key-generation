const expect =  require('chai').expect
const jsc = require('jsverify')
const _ = require('lodash')
const ob = require('ob-js')

const {
  _buf2hex,
  _hex2buf,
  _shardHex,
  _combineHex,
  _shardBuffer,
  _combineBuffer,
  _shardPatq,
  _combinePatq
  } = require('../src')

describe('sharding', () => {
  let hexString = jsc.string.smap(
    str => Buffer.from(str).toString('hex'),
    hex => Buffer.from(hex, 'hex').toString()
  )

  let buffer = jsc.string.smap(
    x => Buffer.from(x),
    x => x.toString
  )

  let patq = hexString.smap(ob.hex2patq, ob.patq2hex)

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

  it('combineHex . shardHex ~ id', () => {
    let rel = jsc.forall(hexString, hex => _combineHex(_shardHex(hex)) === hex)

    jsc.assert(rel)
  })

  it('combinePatq . shardPatq ~ id', () => {
    let rel = jsc.forall(patq, pq => _combinePatq(_shardPatq(pq)) === pq)

    jsc.assert(rel)
  })
})

