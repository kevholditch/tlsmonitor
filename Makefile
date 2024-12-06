.PHONY: test-docker
test-docker:
	docker build --pull --no-cache --progress=plain --platform linux/amd64 -f Dockerfile.test -t tlsmonitor-test .
	docker run --privileged --network host tlsmonitor-test go test -v $(TEST_FLAGS) ./...

# Usage: make test-docker TEST_FLAGS="-run TestTLSHandshakeCapture" 