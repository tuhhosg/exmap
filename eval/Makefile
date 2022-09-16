TESTS = \
	test-bench-alloc \
	test-bench-read  \
	test-bench-steal \
	test-exmap


all: ${TESTS}

clean:
	rm -f ${TESTS}

test-%: test-%.cc
	g++ -o $@  $< -O3 -lpthread -ggdb
