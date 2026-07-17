#include "crypto.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

int denyfs_crypto_init(void) {
    if (sodium_init() == -1) {
        return -1;
    }
    // OpenSSL 1.1.0/3.0+ initializes automatically, but we can verify it works
    return 0;
}

void denyfs_crypto_cleanup(void) {
    // OpenSSL 1.1.0/3.0+ manages its own cleanup, no actions required
}

int denyfs_derive_master_key(const char *password, size_t password_len,
                             const uint8_t *salt, uint8_t *out_master_key) {
    if (password == NULL || salt == NULL || out_master_key == NULL) {
        return -1;
    }
    int res = crypto_pwhash(out_master_key, KEY_SIZE_GCM,
                            password, password_len,
                            salt, ARGON2_OPSLIMIT, ARGON2_MEMLIMIT,
                            crypto_pwhash_ALG_ARGON2ID13);
    return (res == 0) ? 0 : -1;
}

int denyfs_derive_header_key(const uint8_t *master_key, uint8_t *out_header_key) {
    if (master_key == NULL || out_header_key == NULL) {
        return -1;
    }
    
    // Implement HKDF-Expand using HMAC-SHA256 for maximum portability.
    // HKDF-Expand(PRK, info, L) where L = 32.
    // Since output length is exactly 32 bytes (one block of SHA-256),
    // T(1) = HMAC-SHA256(PRK, info || 0x01).
    const char *info = "DenyFS Header Key V1";
    size_t info_len = strlen(info);
    
    uint8_t data[256];
    if (info_len + 1 > sizeof(data)) {
        return -1;
    }
    memcpy(data, info, info_len);
    data[info_len] = 0x01; // Block number 1
    
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), master_key, KEY_SIZE_GCM, data, info_len + 1, out_header_key, &len)) {
        return -1;
    }
    if (len != KEY_SIZE_GCM) {
        return -1;
    }
    return 0;
}

int denyfs_encrypt_header(const denyfs_header_payload_t *payload,
                           const uint8_t *header_key,
                           denyfs_header_disk_t *out_disk_header) {
    if (payload == NULL || header_key == NULL || out_disk_header == NULL) {
        return -1;
    }
    
    // Generate secure random IV
    randombytes_buf(out_disk_header->iv, IV_SIZE);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, header_key, out_disk_header->iv) != 1) goto err;
    
    int len = 0;
    if (EVP_EncryptUpdate(ctx, out_disk_header->ciphertext, &len, 
                           (const uint8_t *)payload, CIPHERTEXT_SIZE) != 1) goto err;
    
    if (EVP_EncryptFinal_ex(ctx, out_disk_header->ciphertext + len, &len) != 1) goto err;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, out_disk_header->tag) != 1) goto err;
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int denyfs_decrypt_header(const denyfs_header_disk_t *disk_header,
                           const uint8_t *header_key,
                           denyfs_header_payload_t *out_payload) {
    if (disk_header == NULL || header_key == NULL || out_payload == NULL) {
        return -1;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) goto err;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, header_key, disk_header->iv) != 1) goto err;
    
    int len = 0;
    if (EVP_DecryptUpdate(ctx, (uint8_t *)out_payload, &len, 
                           disk_header->ciphertext, CIPHERTEXT_SIZE) != 1) goto err;
    
    // Set expected GCM tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)disk_header->tag) != 1) goto err;
    
    int ret = EVP_DecryptFinal_ex(ctx, ((uint8_t *)out_payload) + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    return (ret > 0) ? 0 : -1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int denyfs_crypt_sector(const uint8_t *in_sector, uint8_t *out_sector,
                        uint64_t lba, const uint8_t *key_xts, int encrypt) {
    if (in_sector == NULL || out_sector == NULL || key_xts == NULL) {
        return -1;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    // Format tweak (LBA) as 16-byte little-endian IV
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    for (int i = 0; i < 8; i++) {
        iv[i] = (uint8_t)((lba >> (8 * i)) & 0xFF);
    }
    
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_xts(), NULL, key_xts, iv, encrypt) != 1) goto err;
    
    int out_len = 0;
    if (EVP_CipherUpdate(ctx, out_sector, &out_len, in_sector, SECTOR_SIZE) != 1) goto err;
    
    int final_len = 0;
    if (EVP_CipherFinal_ex(ctx, out_sector + out_len, &final_len) != 1) goto err;
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int denyfs_compute_hmac(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *out_hmac) {
    if (!key || !data || !out_hmac) return -1;
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out_hmac, &len))
        return -1;
    return (len == 32) ? 0 : -1;
}

void *denyfs_secure_alloc(size_t size) {
    return sodium_malloc(size);
}

void denyfs_secure_free(void *ptr, size_t size) {
    if (ptr == NULL) return;
    sodium_memzero(ptr, size);
    sodium_free(ptr);
}
