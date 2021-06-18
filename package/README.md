# minio-crypto-wasm

## install
`npm i minio-crypto-wasm --registry=http://npm.jdjinsui.com`

## usage
```js
const { load, encrypt, decrypt } = require('../package');

load().then(() => {
  const enc = encrypt('123456aA', '{}')
  const dec = decrypt('123456aA', enc)
  console.log(enc, dec)
});
```