.PHONY: test lint
test: policy/parser.go
	go test -v ./policy
	go test -v ./server
	go test -v ./log

policy/parser.go: policy/parser.y
	goyacc -v "" -o policy/parser.go policy/parser.y

lint:
	golangci-lint run ./...

bench:
	go test -bench=. -cpu=1 ./server
	go test -bench=. -benchmem ./server