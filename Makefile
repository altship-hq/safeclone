DIST := ./dist
BINARY_CLI := safeclone
BINARY_SERVER := safeclone-server

.PHONY: build build-cli build-server test test-coverage docker deploy release clean

build: build-cli build-server

build-cli:
	GOOS=linux   GOARCH=amd64 go build -o $(DIST)/$(BINARY_CLI)-linux-amd64   ./cmd/safeclone
	GOOS=darwin  GOARCH=arm64 go build -o $(DIST)/$(BINARY_CLI)-darwin-arm64  ./cmd/safeclone
	GOOS=darwin  GOARCH=amd64 go build -o $(DIST)/$(BINARY_CLI)-darwin-amd64  ./cmd/safeclone
	GOOS=windows GOARCH=amd64 go build -o $(DIST)/$(BINARY_CLI)-windows-amd64.exe ./cmd/safeclone

build-server:
	GOOS=linux GOARCH=amd64 go build -o $(DIST)/$(BINARY_SERVER)-linux-amd64 ./cmd/server

test:
	go test -race ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

docker:
	bash docker/build.sh

deploy:
	scp $(DIST)/$(BINARY_SERVER)-linux-amd64 $(VPS_HOST):/usr/local/bin/$(BINARY_SERVER)
	ssh $(VPS_HOST) "systemctl restart safeclone"

release: build-cli
	gh release create v$$(git describe --tags --abbrev=0) \
		$(DIST)/$(BINARY_CLI)-linux-amd64 \
		$(DIST)/$(BINARY_CLI)-darwin-arm64 \
		$(DIST)/$(BINARY_CLI)-darwin-amd64 \
		$(DIST)/$(BINARY_CLI)-windows-amd64.exe

clean:
	rm -rf $(DIST)
