#ifndef DENYFS_CRYPTO_H
#define DENYFS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define HEADER_SIZE 4096
#define SECTOR_SIZE 4096

#define SALT_SIZE 16
#define IV_SIZE 12
#define TAG_SIZE 16
#define CIPHERTEXT_SIZE (HEADER_SIZE - SALT_SIZE - IV_SIZE - TAG_SIZE)

#define KEY_SIZE_XTS 64  // Two 256-bit keys for AES-256-XTS
#define KEY_SIZE_HMAC 32 // 256-bit key for HMAC-SHA256
#define KEY_SIZE_GCM 32  // 256-bit key for AES-256-GCM

// Argon2id parameters
#define ARGON2_OPSLIMIT 4
#define ARGON2_MEMLIMIT (64 * 1024 * 1024) // 64 MB

#pragma pack(push, 1)

// Plaintext payload wrapped in the header.
// Must fit in CIPHERTEXT_SIZE (4052 bytes).
typedef struct {
    uint64_t magic;             // Sanity check: 0x44656e7946533031 ('DenyFS01')
    uint64_t volume_size;       // Declared volume size in bytes
    uint64_t bitmap_offset;     // Offset to block allocation bitmap
    uint64_t bitmap_size;       // Size of allocation bitmap
    uint8_t volume_key[KEY_SIZE_XTS];  // AES-XTS key
    uint8_t hmac_key[KEY_SIZE_HMAC];   // HMAC key
    uint8_t reserved[CIPHERTEXT_SIZE - 24 - KEY_SIZE_XTS - KEY_SIZE_HMAC]; // Pad to exactly CIPHERTEXT_SIZE
} denyfs_header_payload_t;

// On-disk format of a header (exactly 4096 bytes)
typedef struct {
    uint8_t salt[SALT_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t ciphertext[CIPHERTEXT_SIZE];
} denyfs_header_disk_t;

#pragma pack(pop)

// API Functions

// Initialize the cryptographic libraries (libsodium and OpenSSL).
// Returns 0 on success, non-zero on failure.
int denyfs_crypto_init(void);

// Clean up resources.
void denyfs_crypto_cleanup(void);

// Derive master key from password and salt using Argon2id.
// Returns 0 on success, non-zero on failure.
int denyfs_derive_master_key(const char *password, size_t password_len,
                             const uint8_t *salt, uint8_t *out_master_key);

// Derive the 256-bit GCM header key from the master key.
// Returns 0 on success, non-zero on failure.
int denyfs_derive_header_key(const uint8_t *master_key, uint8_t *out_header_key);

// Encrypt the header payload using AES-256-GCM.
// Returns 0 on success, non-zero on failure.
int denyfs_encrypt_header(const denyfs_header_payload_t *payload,
                           const uint8_t *header_key,
                           denyfs_header_disk_t *out_disk_header);

// Decrypt the header using AES-256-GCM.
// Returns 0 on success, non-zero on failure.
int denyfs_decrypt_header(const denyfs_header_disk_t *disk_header,
                           const uint8_t *header_key,
                           denyfs_header_payload_t *out_payload);

// Encrypt or decrypt a single 4096-byte sector using AES-256-XTS.
// tweak (LBA) is passed as a 64-bit integer.
// encrypt = 1 for encryption, 0 for decryption.
// Returns 0 on success, non-zero on failure.
int denyfs_crypt_sector(const uint8_t *in_sector, uint8_t *out_sector,
                        uint64_t lba, const uint8_t *key_xts, int encrypt);

// Compute HMAC-SHA256(key, data) and write 32 bytes to out_hmac.
// Returns 0 on success, non-zero on failure.
int denyfs_compute_hmac(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *out_hmac);

// Memory hygiene wrappers
void *denyfs_secure_alloc(size_t size);
void denyfs_secure_free(void *ptr, size_t size);

#endif // DENYFS_CRYPTO_H
