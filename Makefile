.PHONY: test lint
test: policy/parser.go
	go test -v ./policy
	go test -v ./server

policy/parser.go: policy/parser.y
	goyacc -v "" -o policy/parser.go policy/parser.y

lint:
	golangci-lint run ./...

