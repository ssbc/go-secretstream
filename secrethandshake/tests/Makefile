server: server.go
	go build server.go

client: client.go
	go build client.go

test: server client
	test -f ../shs1-testsuite/test-server.js || git submodule update --init
	node ../shs1-testsuite/test-server.js ./server
	node ../shs1-testsuite/test-client.js ./client