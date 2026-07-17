#!/bin/bash
#
# Generate seed corpus for AFL++ fuzzing of the DenyFS header parser.
#
# Creates a directory of seed inputs that AFL++ will use as the starting
# corpus. Seeds include:
#   1. A valid encrypted header (created by denyfs)
#   2. An all-zeros header (minimum valid struct)
#   3. An all-0xFF header
#   4. A random-filled header
#   5. A truncated header (short input)
#
# Usage:
#   cd project_root
#   bash tests/gen_fuzz_corpus.sh
#
# Requires: the 'denyfs' binary to be compiled.

set -euo pipefail

CORPUS_DIR="fuzz_corpus_header"
CORPUS_SECTOR_DIR="fuzz_corpus_sector"
HEADER_SIZE=4096
SECTOR_SIZE=4096

echo "[*] Generating header fuzzing seed corpus in ${CORPUS_DIR}/"
mkdir -p "${CORPUS_DIR}"

# Seed 1: Valid header from a real container
SEED_CONTAINER="__seed_corpus_tmp.img"
if [ -f ./denyfs ]; then
    ./denyfs create "${SEED_CONTAINER}" --size 10 --password "seed_corpus_pass" 2>/dev/null || true
    if [ -f "${SEED_CONTAINER}" ]; then
        dd if="${SEED_CONTAINER}" of="${CORPUS_DIR}/valid_header.bin" bs=${HEADER_SIZE} count=1 2>/dev/null
        # Also extract hidden header region (last 32KB → first 4096)
        FILESIZE=$(stat -c%s "${SEED_CONTAINER}" 2>/dev/null || stat -f%z "${SEED_CONTAINER}" 2>/dev/null)
        HIDDEN_OFF=$((FILESIZE - 32768))
        dd if="${SEED_CONTAINER}" of="${CORPUS_DIR}/hidden_region.bin" bs=1 skip=${HIDDEN_OFF} count=${HEADER_SIZE} 2>/dev/null || true
        rm -f "${SEED_CONTAINER}"
        echo "  [+] Seed 1: valid_header.bin (from real container)"
        echo "  [+] Seed 1b: hidden_region.bin (hidden header region)"
    fi
else
    echo "  [!] denyfs binary not found — skipping valid header seed"
fi

# Seed 2: All zeros
dd if=/dev/zero of="${CORPUS_DIR}/all_zeros.bin" bs=${HEADER_SIZE} count=1 2>/dev/null
echo "  [+] Seed 2: all_zeros.bin"

# Seed 3: All 0xFF
python3 -c "import sys; sys.stdout.buffer.write(b'\\xff' * ${HEADER_SIZE})" > "${CORPUS_DIR}/all_ff.bin"
echo "  [+] Seed 3: all_ff.bin"

# Seed 4: Random fill
dd if=/dev/urandom of="${CORPUS_DIR}/random_fill.bin" bs=${HEADER_SIZE} count=1 2>/dev/null
echo "  [+] Seed 4: random_fill.bin"

# Seed 5: Truncated (512 bytes — partial header)
dd if=/dev/urandom of="${CORPUS_DIR}/truncated_512.bin" bs=512 count=1 2>/dev/null
echo "  [+] Seed 5: truncated_512.bin"

# Seed 6: Header with valid salt structure but garbage ciphertext
python3 -c "
import os, sys
salt = os.urandom(16)
iv = os.urandom(12)
tag = os.urandom(16)
ct = os.urandom(${HEADER_SIZE} - 16 - 12 - 16)
sys.stdout.buffer.write(salt + iv + tag + ct)
" > "${CORPUS_DIR}/structured_random.bin"
echo "  [+] Seed 6: structured_random.bin"

echo ""
echo "[*] Generating sector fuzzing seed corpus in ${CORPUS_SECTOR_DIR}/"
mkdir -p "${CORPUS_SECTOR_DIR}"

# Sector seed 1: All zeros
dd if=/dev/zero of="${CORPUS_SECTOR_DIR}/all_zeros.bin" bs=${SECTOR_SIZE} count=1 2>/dev/null
echo "  [+] Seed 1: all_zeros.bin"

# Sector seed 2: Random
dd if=/dev/urandom of="${CORPUS_SECTOR_DIR}/random_sector.bin" bs=${SECTOR_SIZE} count=1 2>/dev/null
echo "  [+] Seed 2: random_sector.bin"

# Sector seed 3: Random sector + 8-byte LBA
dd if=/dev/urandom of="${CORPUS_SECTOR_DIR}/random_with_lba.bin" bs=$((SECTOR_SIZE + 8)) count=1 2>/dev/null
echo "  [+] Seed 3: random_with_lba.bin"

echo ""
echo "[+] Corpus generation complete."
echo "    Header corpus: $(ls ${CORPUS_DIR} | wc -l) seeds in ${CORPUS_DIR}/"
echo "    Sector corpus: $(ls ${CORPUS_SECTOR_DIR} | wc -l) seeds in ${CORPUS_SECTOR_DIR}/"
echo ""
echo "Run AFL++:"
echo "  afl-fuzz -i ${CORPUS_DIR} -o fuzz_findings_header -- ./fuzz_header @@"
echo "  afl-fuzz -i ${CORPUS_SECTOR_DIR} -o fuzz_findings_sector -- ./fuzz_sector @@"
