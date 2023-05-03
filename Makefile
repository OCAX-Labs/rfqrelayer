build:
	@go build -o bin/rfqrelayer -v

run: build
	@./bin/rfqrelayer

test:
	@go test -v ./... -count=1
