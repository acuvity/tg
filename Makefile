MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail
GIT_SHA=$(shell git rev-parse --short HEAD)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
GIT_TAG=$(shell git describe --tags --abbrev=0 --match='v[0-9]*.[0-9]*.[0-9]*' 2> /dev/null | sed 's/^.//')
BUILD_DATE=$(shell date)
VERSION_PKG="go.acuvity.ai/tg/version"
LDFLAGS = -ldflags="-w -s -X '$(VERSION_PKG).GitSha=$(GIT_SHA)' -X '$(VERSION_PKG).GitBranch=$(GIT_BRANCH)' -X '$(VERSION_PKG).GitTag=$(GIT_TAG)' -X '$(VERSION_PKG).BuildDate=$(BUILD_DATE)'"

export GO111MODULE = on

default: lint test

lint:
	golangci-lint run \
		--disable-all \
		--exclude-use-default=false \
		--exclude=dot-imports \
		--exclude=package-comments \
		--exclude=unused-parameter \
		--enable=errcheck \
		--enable=goimports \
		--enable=ineffassign \
		--enable=revive \
		--enable=unused \
		--enable=staticcheck \
		--enable=unconvert \
		--enable=misspell \
		--enable=prealloc \
		--enable=nakedret \
		--enable=unparam \
		./...

test:
	go test ./... -race -cover -covermode=atomic -coverprofile=unit_coverage.out

sec:
	# gosec -quiet -exclude=G304 ./...

build:
	go build $(LDFLAGS) -trimpath .

remod:
	go mod tidy
