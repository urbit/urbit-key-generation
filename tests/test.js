import {
  argon2u,
  fullWalletFromTicket,
  fullWalletFromSeed,
  childNodeFromSeed,
  childSeedFromSeed,
  walletFromSeed,
  urbitKeysFromSeed,
} from '../src/index'

const buf2hex = buffer => {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

test('argon2u', async () => {
  let res = await argon2u({
    entropy: 'password123',
    seedSize: 64,
  })

  expect(res).toBeDefined();
})

test('child seed from seed', async () => {
  let res = await childSeedFromSeed({
    seed: 'some seed',
    type: 'type',
    revision: 0
  });
  expect(buf2hex(res)).toBe('b150354a72552c9efd');
  //
  res = await childSeedFromSeed({
    seed: 'some seed!',
    type: 'type',
    revision: 0
  });
  expect(buf2hex(res)).toBe('d613009d343cfc90b471');
  //
  res = await childSeedFromSeed({
    seed: 'some seed',
    type: 'type',
    revision: 0,
    ship: 2
  });
  expect(buf2hex(res)).toBe('b50817d05c920fa6b3');
  //
  let res2 = await childSeedFromSeed({
    seed: 'some seed',
    type: 'type',
    revision: 0,
    ship: 2,
    password: ''
  });
  expect(res2).toEqual(res);
  //
  res = await childSeedFromSeed({
    seed: 'some seed',
    type: 'type',
    revision: 0,
    ship: 2,
    password: 'pass'
  });
  expect(buf2hex(res)).toBe('8ccb09374028018690');
});

test('wallet from seed', async () => {
  let res = await walletFromSeed('some seed');
  expect(res).toEqual({
    public: '02bb80a59fd51ed853285f3b7738b4542f619a52819a04680e5f36c4d76547eec9',
    private: '733fce1a6a6dc99641590a454532298423c2c65f0df30ca070698d92df55196e',
    chain: 'ef2ccb72ef656cef2256d5fb0a43bbfab04ced88366876580e34e4e57c96c48c'
  });
  //
  let res2 = await walletFromSeed('some seed', '');
  expect(res2).toEqual(res);
  //
  res = await walletFromSeed('some seed', 'pass');
  expect(res).toEqual({
    public: '0201239b9f2b940f7ce29d19633f66bcdd46ddb647812921562aa1e402584cb0a6',
    private: 'f551b64d202e4749d86953d4aa2ee5252093fb335853104bfdd44360c3b95032',
    chain: 'd3ad3620177f98d600c173a30b9a57074dede600ded508b487f29359c684c3dc'
  });
});

test('child node from seed', async () => {
  let res = await childNodeFromSeed({
    seed: 'some seed',
    type: 'type',
    revision: 0
  });
  expect(res.meta).toEqual({type: 'type', revision: 0, ship: null});
  expect(res.seed).toBe('b150354a72552c9efd');
  expect(res.keys).toEqual({
    public: '0343341b3182065677b7c2589e4c71d03b0359d1fb2b42a08a6304db12dff417e7',
    private: 'f344aca1ac4f48a71efcc2555568767e642589a346c7ee8a1a4bab4df0b69386',
    chain: '69a1bf8dc1651f883678e106ba86e07a48f21adb7b1f8ee4b21aa3f8da6784e7'
  });
  //
  res = await childNodeFromSeed({
    seed: 'some seed',
    type: 'type',
    revision: 0,
    ship: 2,
    password: 'pass'
  });
  expect(res.meta).toEqual({type: 'type', revision: 0, ship: 2});
  expect(res.seed).toBe('8ccb09374028018690');
  expect(res.keys).toEqual({
    public: '032be1f970f46034cd811a3245d6688c74e22ae96e5020b7183bf471118b031ca2',
    private: 'a5e3bdb9bed6322a0eb97cac8d5ee0aadd9a39b338e17a53bfd63d67321c0154',
    chain: '37740b089f085cc7a04e1f4478c5f528e814f92f979b79c625b5c01272f3e44c'
  });
});

test('urbit keys from seed', async () => {
  let seed = Buffer.from('some seed');
  let res = urbitKeysFromSeed(seed, Buffer.from(''));
  expect(res.crypt).toEqual({
    private: '15ef9b020606faf25dd4b622d34a5f2ba83e3498f78e35c6d256379f4871391e',
    public: '220c0db4f436d2532f0fddb56555bf6926d6bcfb073d790b8f1e9c4258ebb43e'
  });
  expect(res.auth).toEqual({
    private: 'fd816b63558f3f4ee5eafedbabe56293ee1f64e837f081724bfdd47d6e4b9815',
    public: 'bbba375a6dd28dc9e44d6a98c75edeb699c10d78e92ccad78c892efa2466c666'
  });
  //
  res = urbitKeysFromSeed(seed, Buffer.from('pass'));
  expect(res.crypt).toEqual({
    private: 'e3ec05249eaaffbfca918dd9048a03656b68e5685f9a2452850917e2b34996ed',
    public: 'edb31a2d442b50d37983ac06ab7c5d976a71eca84ed16573bf6e258b082ea9f9'
  });
  expect(res.auth).toEqual({
    private: '5dee3371f15af6dfdd4c8c50037c3f3350e26440af3257ed62f9da9445e9946b',
    public: '9b4931daf2c0cccd34df0772f70eaaa9b5b341c46e1a8cbf063b7cdd25917e13'
  });
});
