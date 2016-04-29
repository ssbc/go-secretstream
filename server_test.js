var createNode = require('secret-handshake/net')
var fs = require('fs')
var pull = require("pull-stream")
var toPull = require('stream-to-pull-stream')

function readKeyF (fname) {
  var tmpobj = JSON.parse(fs.readFileSync(fname).toString())
  return {
    'publicKey': new Buffer(tmpobj.publicKey, 'base64'),
    'secretKey': new Buffer(tmpobj.secretKey, 'base64'),
  }
}

var bobKey = readKeyF('key.bob.json')
var bob = createNode({
  keys: bobKey,
  appKey: new Buffer('IhrX11txvFiVzm+NurzHLCqUUe3xZXkPfODnp7WlMpk=', 'base64'),
  // the authenticate function is required to receive calls.
  authenticate: function (pub, cb) {
    // decide whether to allow access to pub.
    console.log('got pub:', pub.toString('base64'))
    if (true) cb(null, true)
    else cb(new Error('reasonzz'))
  // The client WILL NOT see the unauthentication reason
  }
})

// now, create a server (bob) and connect a client (alice)

console.log('creating server')
bob.createServer(function (shsNetThingy) {
//   console.dir(arguments)
  console.log('ohai')
  pull(shsNetThingy, toPull.sink(process.stdout))
}).listen(8978, function () {
  console.log('listening')
})
