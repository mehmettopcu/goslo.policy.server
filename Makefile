.PHONY: test
test: policy/parser.go
	go test -v ./policy

policy/parser.go: policy/parser.y
	goyacc -v "" -o policy/parser.go policy/parser.y

