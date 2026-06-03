APP_NAME := cftunn
SRC := $(shell find . -name "*.go")
PREFIX ?= /usr/local

.PHONY: all build clean install uninstall release release-check

all: build

build: $(APP_NAME)

$(APP_NAME): $(SRC)
	go build -o $(APP_NAME) .

install: $(APP_NAME)
	install -d $(PREFIX)/bin
	install -m 755 $(APP_NAME) $(PREFIX)/bin/$(APP_NAME)

uninstall:
	rm -f $(PREFIX)/bin/$(APP_NAME)

clean:
	rm -f $(APP_NAME)

# Dry-run a release locally (builds + formula, no tag/publish required)
release-check:
	GITHUB_TOKEN=$$(gh auth token) goreleaser release --clean --snapshot --skip=publish

# Cut a real release: builds binaries, creates GitHub Release, updates Homebrew tap.
# Requires a vX.Y.Z tag to be pushed first (see CLAUDE.md).
release:
	GITHUB_TOKEN=$$(gh auth token) goreleaser release --clean
