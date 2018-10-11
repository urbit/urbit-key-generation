const expect =  require('chai').expect
const jsc = require('jsverify')
const _ = require('lodash')
const ob = require('urbit-ob')
const lodash = require('lodash')

const {
  _buf2hex,
  _hex2buf,
  _shardHex,
  _combineHex,
  _shardBuffer,
  _combineBuffer,
  _shardsConsistent,
  shardPatq,
  combinePatq
  } = require('../src')

const hexString = jsc.nestring.smap(
  str => Buffer.from(str).toString('hex'),
  hex => Buffer.from(hex, 'hex').toString()
)

const buffer = jsc.nearray(jsc.uint8).smap(
  arr => Buffer.from(arr),
  buf => Array.from(buf)
)

const patq = hexString.smap(ob.hex2patq, ob.patq2hex)

const shardable = jsc.oneof([
    jsc.pair(patq, jsc.constant('patq')),
    jsc.pair(hexString, jsc.constant('hex'))
  ])

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
    let rel = jsc.forall(buffer, buf =>
      _.isEqual(_combineBuffer(_shardBuffer(buf)), buf))

    jsc.assert(rel, { tests: 250 })
  })

  it('combineHex . shardHex ~ id', () => {
    let rel = jsc.forall(hexString, hex =>
      _combineHex(_shardHex(hex)) === hex)

    jsc.assert(rel, { tests: 250 })
  })

  it('combinePatq . shardPatq ~ id', () => {
    let rel = jsc.forall(patq, pq => {
      let combined = combinePatq(shardPatq(pq))
      return ob.eqPatq(combined, pq)
    })

    jsc.assert(rel, { tests: 250 })
  })

  it('2/3 shards always sufficient for recovery', () => {
    let rel = jsc.forall(shardable, inp =>
      inp[1] === 'patq'
      ? _shardsConsistent(combinePatq, inp[0], ob.eqPatq, shardPatq(inp[0]))
      : _shardsConsistent(_combineHex, inp[0], lodash.isEqual, _shardHex(inp[0]))
    )

    jsc.assert(rel, { tests: 250 })
  })
})

