VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-pg e2e lint demo generate clean

build: ## build chautari and mock-llm into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/chautari ./cmd/chautari
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/mock-llm ./cmd/mock-llm

test: ## run the whole suite offline
	go test -race ./...

test-pg: ## run the suite including Postgres integration tests (starts a throwaway container)
	docker run -d --rm --name chautari-test-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=chautari_test -p 55432:5432 postgres:16-alpine
	until docker exec chautari-test-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	CHAUTARI_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:55432/chautari_test?sslmode=disable go test -race ./... ; \
	  status=$$?; docker stop chautari-test-pg >/dev/null; exit $$status

e2e: ## end to end through a real agentgateway binary (AGENTGATEWAY=/path/to/agentgateway)
	scripts/e2e-agentgateway.sh

lint: ## gofmt + vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

demo: ## the full demo stack
	docker compose up --build

generate: build ## regenerate the example stack into out/
	./bin/chautari generate examples/himalayan-bank.cdl -o out --demo

clean:
	rm -rf bin out
