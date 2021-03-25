generate:
	go get -u golang.org/x/tools/cmd/stringer
	go generate ./...

deps:
	go mod download
	go mod tidy

run:
	go run cmd/authorize/main.go

lint:
	golangci-lint -v run