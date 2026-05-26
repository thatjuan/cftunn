APP_NAME := cftunn
SRC := $(shell find . -name "*.go")
PREFIX ?= /usr/local

.PHONY: all build clean install uninstall

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
