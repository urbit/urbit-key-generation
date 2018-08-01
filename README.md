```
npm install
```

```
> kg = require('.')
> kg.generateFullWallet('16+ bytes entropy', 1, 1, 1).then(console.log).catch(console.error)
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
        '02d60fd37b79766fa46f7c812ea91574a3ee7d88edafe6438a4b314d6c935dd68d',
       private:
        'f88b21561cb8ffd57614ec0b6c2474e8de3ecd1894efdd495c503a8b616f46ca',
       chain:
        '33049cb88c52f72119d402a04ef522204feeaab3e4193015986b5877847449f1' } ],
  spawnKeys:
   [ { public:
        '02ed8202727883438c5f8f94f56da65fa617ce638a3c2c95647133441e9e6b236a',
       private:
        '2c41a0ec72d3a7e121340fde98674c02c8a2f5a3ba66e97d38aea3f24f5b0531',
       chain:
        '3865d59bc99ab15c06e830342d8f021e1a4e1e3dd434b35a2804f90d4e4ea3ec' } ],
  manageKeys:
   [ { public:
        '029a18c0ff96fc3fc1964fbc09463272747b9a87d4fefbd093b7da7e942b242d23',
       private:
        'eda1d902a583d55eaaac578f62789e9c05363d611e1693c8f1df986dea01fbc9',
       chain:
        '43b6c27b3a79645816080dbd9d643366ef7f6aa67a6ba0abb75279a10bbf1d4b' } ],
  liveKeys:
   [ { auth:
        { public:
           '42a8bb603f84293f7e0ea6925a4c5eefc6f28fc8e8182f611eda41fb6b7a2376',
          private:
           '5b683e3def02b0e57f208af7fe8064d0df008fd718340a996530feb61f48816c42a8bb603f84293f7e0ea6925a4c5eefc6f28fc8e8182f611eda41fb6b7a2376' },
       crypt:
        { public:
           '42a8bb603f84293f7e0ea6925a4c5eefc6f28fc8e8182f611eda41fb6b7a2376',
          private:
           '5b683e3def02b0e57f208af7fe8064d0df008fd718340a996530feb61f48816c42a8bb603f84293f7e0ea6925a4c5eefc6f28fc8e8182f611eda41fb6b7a2376' } } ] }
```
