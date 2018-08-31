import { argon2u } from '../dist/index'
// import Buffer from 'buffer'

test('test argon2u', async () => {
  const data = await argon2u(Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]), 32)
  console.log(data)
  return expect(data.toBeDefined())
})
