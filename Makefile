APP_NAME := cftunn
SRC := $(shell find . -name "*.go")

.PHONY: all build clean

all: build

build: $(APP_NAME)

$(APP_NAME): $(SRC)
	go build -o $(APP_NAME) .

clean:
	rm -f $(APP_NAME)
