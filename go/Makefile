.PHONY: all build_docker compile

IMGNAME := build_go

all: build_docker compile

build_docker:
	docker build -t $(IMGNAME):latest -f Dockerfile .

compile: build_docker
	docker run --rm -v "$(shell pwd):/workspace" -it $(IMGNAME)
