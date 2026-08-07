.PHONY: test test-watch start start-dev docker-build docker-run clean help

help:           ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

test:           ## Run all tests
	node --test

test-watch:     ## Run tests in watch mode
	npx --yes nodemon --exec "node --test" --ext js,json

start:          ## Start the server (default port 4188)
	node server.js

start-dev:      ## Start with env-check on startup
	MONA_ENV_CHECK=1 node server.js

docker-build:   ## Build Docker image
	docker build -t mona-expert .

docker-run:     ## Run Docker container (port 4188)
	docker run -p 4188:4188 --rm mona-expert

lint:           ## Check for common issues
	node --check server.js
	node --check src/*.js

clean:          ## Remove generated files
	rm -rf .mona-dashboard/
	rm -f .mona-audit-key
