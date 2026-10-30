.PHONY: build test lint health tidy clean

BIN := bin/critforge

build:
	go build -o $(BIN) ./cmd/critforge

test:
	go test ./...

lint:
	go vet ./...
	gofmt -l . | (! grep .) || (echo "gofmt needed on files above"; exit 1)

health: build
	./$(BIN) health --scope scope.example.yaml --actor ci

tidy:
	go mod tidy

clean:
	rm -rf bin critforge-audit.jsonl
