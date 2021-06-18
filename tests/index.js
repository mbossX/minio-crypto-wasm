require('./wasm_exec')

const start = async function start() {
  const go = new Go()
  const result = await WebAssembly.instantiate(fs.readFileSync('../mcw.wasm'), go.importObject)
  go.run(result.instance);
  const enc = mcw_encrypt('123456aA', '{}')
  const dec = mcw_decrypt('123456aA', enc)
  console.log(enc, dec)
}
start()
