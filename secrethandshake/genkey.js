// SPDX-FileCopyrightText: 2021 The Secretstream Authors
//
// SPDX-License-Identifier: MIT

var sodium = require('chloride')
var k = sodium.crypto_sign_keypair()

console.log(JSON.stringify({
    "publicKey":k.publicKey.toString("base64"),
    "secretKey":k.secretKey.toString("base64"),
}))

