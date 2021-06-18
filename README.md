# minio-crypto-wasm
minio secure io en/decrypt lib with go wasm.

# build

`GOOS=js GOARCH=wasm go build -o mcw.wasm main.go`

# test

`cd tests && node index.js`