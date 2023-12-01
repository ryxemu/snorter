NAME := snorter

VERSION := 0.0.1

run:
	cd bin && sudo ./${NAME}
build:
	mkdir -p bin
	go build -o bin/${NAME} main.go


# build all supported versions
build-all: build-prepare build-linux build-darwin build-windows

# prep for building
build-prepare:
	@echo "Preparing ${NAME} ${VERSION}"
	@rm -rf bin/*
	@-mkdir -p bin/

# make a darwin binary
build-darwin:
	@echo "build-darwin: building ${VERSION}"
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=pie -ldflags="-X main.Version=${VERSION} -s -w" -o bin/${NAME}-darwin main.go

# make a linux binary
build-linux:
	@echo "build-linux: building ${VERSION}"
	go env
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Version=${VERSION} -s -w" -o bin/${NAME}-linux main.go

#make a windows binary
build-windows:
	@echo "build-windows: building ${VERSION}"
	GOOS=windows GOARCH=amd64 go build -buildmode=pie -ldflags="-X main.Version=${VERSION} -s -w" -o bin/${NAME}-windows.exe main.go
	@#GOOS=windows GOARCH=386 go build -buildmode=pie -ldflags="-X main.Version=${VERSION} -s -w" -o bin/${NAME}-windows-x86.exe main.go


# CICD triggers this
set-version-%:
	@echo "VERSION=${VERSION}.$*" >> $$GITHUB_ENV