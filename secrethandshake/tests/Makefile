clean:
	rm server
	rm client

server: server.go
	go build server.go

client: client.go
	go build client.go

test: server client
	test -d ../shs1-testsuite/node_modules || \
		( git submodule update --init && \
		pushd ../shs1-testsuite && \
		npm ci && \
		popd )
	node ../shs1-testsuite/test-server.js ./server
	node ../shs1-testsuite/test-client.js ./client
