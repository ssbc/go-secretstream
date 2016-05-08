var boxes = require('pull-box-stream')
var pull = require('pull-stream')
var toPull = require('stream-to-pull-stream')

pull(
    toPull.source(process.stdin),
    boxes.createBoxStream(Buffer(process.argv[2], "base64"), Buffer(process.argv[3], "base64")),
    toPull.sink(process.stdout)
)
