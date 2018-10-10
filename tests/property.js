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

const hexString = jsc.nestring.smap(
  str => Buffer.from(str).toString('hex'),
  hex => Buffer.from(hex, 'hex').toString()
)

const buffer = jsc.nearray(jsc.uint8).smap(
  arr => Buffer.from(arr),
  buf => Array.from(buf)
)

const patq = hexString.smap(ob.hex2patq, ob.patq2hex)

removeLeadingZeroBytes = str =>
  str.slice(0, 2) === '00'
  ? removeLeadingZeroBytes(str.slice(2))
  : str

eqModLeadingZeroBytes = (s, t) =>
  removeLeadingZeroBytes(s) === removeLeadingZeroBytes(t)

eqPatq = (p, q) => {
  phex = ob.patq2hex(p)
  qhex = ob.patq2hex(q)
  return eqModLeadingZeroBytes(phex, qhex)
}

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
      let combined = _combinePatq(_shardPatq(pq))
      return eqPatq(combined, pq)
    })

    jsc.assert(rel, { tests: 250 })
  })
})

