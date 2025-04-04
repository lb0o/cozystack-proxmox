.PHONY: build test clean release

# Build the cozy-secret binary
build:
	go build -o cozy-secret

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -f cozy-secret
	rm -f coverage.out
	rm -f coverage.html

# Create release build and generate MD5 checksum
release: build
	md5sum cozy-secret > cozy-secret.md5 