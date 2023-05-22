all: module memory_pool eval

module:
	make -C module/

memory_pool:
	make -C memory_pool/

eval:
	make -C eval/

.PHONY: module memory_pool eval
