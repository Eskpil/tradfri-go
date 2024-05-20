GOFILES = $(shell find . -name '*.go' -not -path './vendor/*')
GOPACKAGES = $(shell go list ./...  | grep -v /vendor/)
TEST_RESULTS=/tmp/test-results

default: format build test vet

.PHONY: fmt
fmt:
	go fmt

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	mkdir -p ${TEST_RESULTS}
	@go test -coverprofile=${TEST_RESULTS}/unittest.out -v $(GOPACKAGES)
	@go tool cover -html=${TEST_RESULTS}/unittest.out -o ${TEST_RESULTS}/unittest-coverage.html
	rm -f ${TEST_RESULTS}/unittest.out

.PHONY: build
build:
	go build -o tradfri-go

.PHONY: release
release:
	mkdir -p dist
	GO111MODULE=on go build -o dist/tradfri-go-darwin-amd64
	GO111MODULE=on;GOOS=linux;go build -o dist/tradfri-go-linux-amd64
	GO111MODULE=on;GOOS=windows;go build -o dist/tradfri-go-windows-amd64
	GO111MODULE=on;GOOS=linux GOARCH=arm GOARM=5;go build -o dist/tradfri-go-linux-arm5

.PHONY: run
run: build
	./dist/tradfri-darwin-amd64

.PHONY: lint
lint: fmt
	docker run --rm -v $(pwd):/app -w /app golangci/golangci-lint:v1.58.2 golangci-lint run -v