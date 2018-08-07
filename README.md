```
npm install
```

```
> kg = require('.')
> kg.generateFullWallet('16+ bytes entropy', [1]).then(console.log).catch(console.error)
Promise { ... }
{ owner:
   { public:
      '026aeb8e10b0af517f1cf9f397ba218affc0e36dd1d049db59361649c2d2f4a9e8',
     private:
      '5cb291e57379aea4ff9aca7b9867d21e78223a859d19124bc50ebd97f88b5b78',
     chain:
      'a513838d35e2d26aeee6e742a5a616395c317cbfc15b0835a4492e8a9633404a' },
  transferKeys:
   [ { public:
        '022ca29b0c5917896d32500b34e9e6a9f654f629ddfb9e75b149fec14394a87e7f',
       private:
        '0fd2d05f404dc0fe29cb9753255567326d4489295b058f0ff9be70aa441b5d7d',
       chain:
        '17e2c784d2358c50df4437708a9952841836bd0f53f5a2061e57ecf436cd610b' } ],
  spawnKeys:
   [ { public:
        '03faf7091d69d4bf9c19a03b56d55932d3fd72506b83bba535c469dc642b0b0546',
       private:
        '37fe5e06283fbc60f800a8042dde69272247e21a3f8f7db2d1ed58e51622eca6',
       chain:
        'd9a1c49465a52148b072eacef40403793c6de0859cc2d2bcc2673130ff178ce5' } ],
  manageKeys:
   [ { public:
        '0354a10b954ae4a3d4ff901e2cec87656f62d9a42d5bb538fba00f39efe2872873',
       private:
        'b61d78c8c3114d689579603bf2d6c85351c284a6c1e4a72948f73a98768eee20',
       chain:
        '36863615a3ef8692d0b6379466485b5e9c4a8c95b2f505c87ac37986be76debe' } ],
  urbitKeys:
   { crypt:
      { private:
         'dad3c87827dd85b619b1a48fd111c72e3729ec9b65365331b6f065fed2115fef',
        public:
         '45dba1df79d35ed80614eb929a707b87cd264d3c908af98d81df8c6a29e93ecd' },
     auth:
      { private:
         '076b0e12e8696bc092a6441b9da71c0f146ebd38ba43f5299433377777154e9f',
        public:
         '36ecfa7d385e29e354692ed79e5b3bb34483f2c390b9dcdc4cd580ed6bd1a3e7' } } ] }
```
