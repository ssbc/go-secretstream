# secretstream [![Build Status](https://travis-ci.org/cryptoscope/secretstream.svg?branch=master)](https://travis-ci.org/cryptoscope/secretstream) [![GoDoc](https://godoc.org/go.cryptoscope.co/secretstream?status.svg)](https://godoc.org/go.cryptoscope.co/secretstream) [![Go Report Card](https://goreportcard.com/badge/go.cryptoscope.co/secretstream)](https://goreportcard.com/report/go.cryptoscope.co/secretstream) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Go implementation of [dominic](@EMovhfIrFk4NihAKnRNhrfRaqIhBv1Wj8pTxJNgvCCY=.ed25519)'s [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake).

Two instances of go-shs can secretly shake hands over a connection. The implementation is compatible with the JS implementation. Run `npm ci && go test -tags interop_nodejs` on the `secrethandshake` and `boxstream` sub-packages.
