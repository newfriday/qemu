DIST ?= oe1
PROJECT_TOP_DIR := $(shell git rev-parse --show-toplevel)

all: binary

dev-image-base:
	docker build -t qemu-upstream-builder:latest -f Dockerfile.${DIST} .

dev-image: dev-image-base
	docker build -t qemu-upstream-builder-dev:latest -f Dockerfile-dev.${DIST} .

binary:
	docker run -v $(PROJECT_TOP_DIR):/home -w /home qemu-upstream-builder-dev:1.0 /bin/bash -c /home/binary-build/build.sh
