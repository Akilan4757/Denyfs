CC ?= gcc
CFLAGS = -Wall -Wextra -g -fsanitize=address,undefined -Isrc
LDFLAGS = -fsanitize=address,undefined
RELEASE_CFLAGS = -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Isrc
LIBS = -lsodium -lcrypto

FUSE_CFLAGS = $(shell pkg-config --cflags fuse3 2>/dev/null)
FUSE_LIBS   = $(shell pkg-config --libs fuse3 2>/dev/null)

SRC_DIR = src
TEST_DIR = tests

all: denyfs denyfs-release test_crypto test_volume test_fs test_timing test_stress fuzz_header fuzz_sector test_bench

# Main binary (with FUSE)
denyfs: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(SRC_DIR)/fuse_ops.c $(SRC_DIR)/main.c
	$(CC) $(CFLAGS) $(FUSE_CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS) $(FUSE_LIBS)

# Release CLI: optimized and hardened, without development sanitizers.
denyfs-release: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(SRC_DIR)/fuse_ops.c $(SRC_DIR)/main.c
	$(CC) $(RELEASE_CFLAGS) $(FUSE_CFLAGS) $^ -o $@ $(LIBS) $(FUSE_LIBS)

release: denyfs-release

# Local browser dashboard for Linux/WSL2 with FUSE enabled.
dashboard: release
	python3 dashboard/server.py

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

# Phase 7: stress tests and seeded correctness
test_stress: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(TEST_DIR)/test_stress.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 7: AFL++ header crypto fuzzing harness (not a full volume-open parser fuzzer)
# For AFL++: CC=afl-gcc make fuzz_header (or afl-clang-fast)
fuzz_header: $(SRC_DIR)/crypto.c $(TEST_DIR)/fuzz_header.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 7: AFL++ sector crypto fuzzing harness
fuzz_sector: $(SRC_DIR)/crypto.c $(TEST_DIR)/fuzz_sector.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

# Phase 8: benchmarks (compiled with -O2, no ASan, for accurate timing)
test_bench: $(SRC_DIR)/crypto.c $(SRC_DIR)/fs.c $(TEST_DIR)/test_bench.c
	$(CC) -Wall -Wextra -O2 -Isrc $^ -o $@ -lsodium -lcrypto

test: test_crypto test_volume test_fs test_timing test_stress
	./test_crypto
	./test_volume
	./test_fs
	./test_timing
	./test_stress

# Optional integration check; requires /dev/fuse and fusermount3.
test-fuse: denyfs-release
	bash $(TEST_DIR)/test_fuse_mount.sh ./denyfs-release

clean:
	rm -f denyfs denyfs-release test_crypto test_volume test_fs test_timing test_stress fuzz_header fuzz_sector test_bench
	rm -f test_volume.img test_fs.img test_corrupt.img timing_outer_only.img timing_both.img test_stress.img bench_container.img
	rm -f __seed_corpus_tmp.img

.PHONY: all clean test test-fuse release dashboard
