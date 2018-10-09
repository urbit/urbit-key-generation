const expect =  require('chai').expect
const jsc = require('jsverify')
const _ = require('lodash')
const ob = require('urbit-ob')

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

const arrayMinBytes = n => jsc.tuple(new Array(n).fill(jsc.uint8))

const hexString = jsc.string.smap(
  str => Buffer.from(str).toString('hex'),
  hex => Buffer.from(hex, 'hex').toString()
)

const hexStringN = n => arrayMinBytes(n).smap(
  arr => Buffer.from(arr).toString('hex'),
  hex => Array.from(Buffer.from(hex, 'hex'))
)

const buffer = jsc.array(jsc.uint8).smap(
  arr => Buffer.from(arr),
  buf => Array.from(buf)
)

const bufferN = n => arrayMinBytes(n).smap(
  arr => Buffer.from(arr),
  buf => Array.from(buf)
)

const patq = n => hexStringN(n).smap(ob.hex2patq, ob.patq2hex)

describe('sharding', () => {
  it('hex2buf and buf2hex are inverses', () => {
    let iso0 = jsc.forall(hexString, hex =>
      _buf2hex(_hex2buf(hex)) === hex)
    let iso1 = jsc.forall(buffer, buf =>
      _.isEqual(_hex2buf(_buf2hex(buf)), buf))

    jsc.assert(iso0)
    jsc.assert(iso1)
  })

  it('combineBuffer . shardBuffer ~ id', () => {
    let rel = gen => jsc.forall(gen, buf =>
      _.isEqual(_combineBuffer(_shardBuffer(buf)), buf))

    jsc.assert(rel(bufferN(16)), { tests: 250 })
    jsc.assert(rel(bufferN(32)), { tests: 250 })
    jsc.assert(rel(bufferN(48)), { tests: 250 })
  })

  it('combineHex . shardHex ~ id', () => {
    let rel = gen =>
      jsc.forall(gen, hex => _combineHex(_shardHex(hex)) === hex)

    jsc.assert(rel(hexStringN(32)), { tests: 250 })
    jsc.assert(rel(hexStringN(64)), { tests: 250 })
    jsc.assert(rel(hexStringN(96)), { tests: 250 })
  })

  it('combinePatq . shardPatq ~ id', () => {
    let rel = gen =>
      jsc.forall(gen, pq => _combinePatq(_shardPatq(pq)) === pq)

    jsc.assert(rel(patq(32), { tests: 250 }))
    jsc.assert(rel(patq(64), { tests: 250 }))
    jsc.assert(rel(patq(96), { tests: 250 }))
  })
})

