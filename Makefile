NAME := snorter

run:
	cd bin && sudo ./${NAME}
build:
	mkdir -p bin
	go build -o bin/${NAME} main.go

build-windows:
	GOOS=windows go build -o bin/${NAME}.exe main.go