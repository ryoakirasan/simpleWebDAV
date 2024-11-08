# Makefile
BINARY_NAME=simpleWebDAV
build:
	@echo "Building for Windows (amd64)..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/$(BINARY_NAME)_windows_amd64.exe .
	@echo "Building for Linux (amd64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY_NAME)_linux_amd64 .
	@echo "Building for Linux (arm64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/$(BINARY_NAME)_linux_arm64 .
clean:
	@echo "Cleaning up..."
	rm -rf bin/*
	
.PHONY: build clean