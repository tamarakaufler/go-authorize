deps:
	go mod download
	go mod tidy

generate:
	go get -u golang.org/x/tools/cmd/stringer
	go generate ./...

lint:
	golangci-lint -v run

run:
	go run cmd/authorize/main.go

all: deps generate lint run

.PHONY:
	deps, generate, lint, run