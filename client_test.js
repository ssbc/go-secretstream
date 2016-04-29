var createNode = require('secret-handshake/net')
var fs = require('fs')
var pull = require('pull-stream')


function readKeyF (fname) {
  var tmpobj = JSON.parse(fs.readFileSync(fname).toString())
  return {
    'publicKey': new Buffer(tmpobj.publicKey, 'base64'),
    'secretKey': new Buffer(tmpobj.secretKey, 'base64'),
  }
}

var alice = readKeyF('key.alice.json')
var bob = readKeyF('key.bob.json')

var alice = createNode({
  keys: alice,
  appKey: new Buffer('IhrX11txvFiVzm+NurzHLCqUUe3xZXkPfODnp7WlMpk=', 'base64'),
})
console.log('dialing...')
var stream = alice.connect({port: 8978, host: 'localhost', key: bob.publicKey}, function (err,stumb) {
  if (err) throw err
  console.log('dialed!')
  pull(pull.values(['hello', 'world']), stumb)
})


