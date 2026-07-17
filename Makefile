CC ?= gcc
CFLAGS = -Wall -Wextra -g -fsanitize=address,undefined -Isrc
LDFLAGS = -fsanitize=address,undefined
LIBS = -lsodium -lcrypto

FUSE_CFLAGS = $(shell pkg-config --cflags fuse3 2>/dev/null)
FUSE_LIBS   = $(shell pkg-config --libs fuse3 2>/dev/null)

SRC_DIR = src
TEST_DIR = tests

all: denyfs test_crypto test_volume test_fs test_timing test_stress fuzz_header fuzz_sector test_bench

# Main binary (with FUSE)
denyfs: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(SRC_DIR)/fuse_ops.c $(SRC_DIR)/main.c
	$(CC) $(CFLAGS) $(FUSE_CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS) $(FUSE_LIBS)

# Phase 1: crypto core tests
test_crypto: $(SRC_DIR)/crypto.c $(TEST_DIR)/test_crypto.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 2: raw volume sector tests
test_volume: $(SRC_DIR)/crypto.c $(TEST_DIR)/test_volume.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 3: filesystem layer tests (no FUSE dependency)
test_fs: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(TEST_DIR)/test_fs.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 4: timing indistinguishability test
test_timing: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(TEST_DIR)/test_timing.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS) -lm

# Phase 6: stress tests and seeded correctness
test_stress: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(TEST_DIR)/test_stress.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 6: AFL++ header parser fuzzing harness
# For AFL++: CC=afl-gcc make fuzz_header (or afl-clang-fast)
fuzz_header: $(SRC_DIR)/crypto.c $(TEST_DIR)/fuzz_header.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 6: AFL++ sector crypto fuzzing harness
fuzz_sector: $(SRC_DIR)/crypto.c $(TEST_DIR)/fuzz_sector.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 7: benchmarks (compiled with -O2, no ASan, for accurate timing)
test_bench: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(TEST_DIR)/test_bench.c
	$(CC) -Wall -Wextra -O2 -Isrc $^ -o $@ -lsodium -lcrypto

test: test_crypto test_volume test_fs test_timing test_stress
	./test_crypto
	./test_volume
	./test_fs
	./test_timing
	./test_stress

clean:
	rm -f denyfs test_crypto test_volume test_fs test_timing test_stress fuzz_header fuzz_sector test_bench
	rm -f test_volume.img test_fs.img test_corrupt.img timing_outer_only.img timing_both.img test_stress.img bench_container.img
	rm -f __seed_corpus_tmp.img

.PHONY: all clean test
