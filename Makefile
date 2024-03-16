BINARY_NAME=knox-am
BUILD_DIR=build

build:
	mkdir -p ${BUILD_DIR}
	GOARCH=amd64 GOOS=linux go build -o ${BUILD_DIR}/$(BINARY_NAME)-linux -v cmd/main.go

clean:
	go clean
	rm -r ${BUILD_DIR}

run:
	go run cmd/main.go

all: clean build
