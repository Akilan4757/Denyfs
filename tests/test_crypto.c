#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>
#include "crypto.h"

// Simple NIST-like consistency test for AES-256-GCM
void test_gcm_correctness(void) {
    printf("[*] Testing AES-256-GCM...\n");
    
    uint8_t *key = denyfs_secure_alloc(KEY_SIZE_GCM);
    assert(key != NULL);
    randombytes_buf(key, KEY_SIZE_GCM);
    
    denyfs_header_payload_t original_payload;
    memset(&original_payload, 0x55, sizeof(original_payload));
    original_payload.magic = 0x44656e7946533031ULL;
    original_payload.volume_size = 1024 * 1024 * 50; // 50MB
    original_payload.bitmap_offset = 8192;
    original_payload.bitmap_size = 2048;
    
    denyfs_header_disk_t disk_header;
    memset(&disk_header, 0, sizeof(disk_header));
    
    // Encrypt
    int res = denyfs_encrypt_header(&original_payload, key, &disk_header);
    assert(res == 0);
    
    // Decrypt
    denyfs_header_payload_t decrypted_payload;
    memset(&decrypted_payload, 0, sizeof(decrypted_payload));
    res = denyfs_decrypt_header(&disk_header, key, &decrypted_payload);
    assert(res == 0);
    
    // Verify correctness
    assert(decrypted_payload.magic == original_payload.magic);
    assert(decrypted_payload.volume_size == original_payload.volume_size);
    assert(decrypted_payload.bitmap_offset == original_payload.bitmap_offset);
    assert(decrypted_payload.bitmap_size == original_payload.bitmap_size);
    assert(memcmp(decrypted_payload.volume_key, original_payload.volume_key, KEY_SIZE_XTS) == 0);
    
    // Test tampering detection
    disk_header.ciphertext[10] ^= 0xFF; // flip a byte
    res = denyfs_decrypt_header(&disk_header, key, &decrypted_payload);
    assert(res != 0); // Decryption must fail!
    
    disk_header.ciphertext[10] ^= 0xFF; // restore byte
    res = denyfs_decrypt_header(&disk_header, key, &decrypted_payload);
    assert(res == 0); // Decryption must pass again
    
    disk_header.tag[5] ^= 0xFF; // tamper tag
    res = denyfs_decrypt_header(&disk_header, key, &decrypted_payload);
    assert(res != 0); // Decryption must fail
    
    denyfs_secure_free(key, KEY_SIZE_GCM);
    printf("[+] AES-256-GCM test passed successfully.\n");
}

// Consistency test for AES-256-XTS sector encryption
void test_xts_correctness(void) {
    printf("[*] Testing AES-256-XTS...\n");
    
    uint8_t *key = denyfs_secure_alloc(KEY_SIZE_XTS);
    assert(key != NULL);
    randombytes_buf(key, KEY_SIZE_XTS);
    
    uint8_t *plain = malloc(SECTOR_SIZE);
    uint8_t *cipher1 = malloc(SECTOR_SIZE);
    uint8_t *cipher2 = malloc(SECTOR_SIZE);
    uint8_t *decrypted = malloc(SECTOR_SIZE);
    assert(plain != NULL && cipher1 != NULL && cipher2 != NULL && decrypted != NULL);
    
    // Fill plain with random pattern
    randombytes_buf(plain, SECTOR_SIZE);
    
    // Encrypt sector LBA 0
    int res = denyfs_crypt_sector(plain, cipher1, 0, key, 1);
    assert(res == 0);
    
    // Decrypt sector LBA 0
    res = denyfs_crypt_sector(cipher1, decrypted, 0, key, 0);
    assert(res == 0);
    assert(memcmp(plain, decrypted, SECTOR_SIZE) == 0);
    
    // Encrypt sector LBA 1 (same plain, should yield different cipher due to tweak)
    res = denyfs_crypt_sector(plain, cipher2, 1, key, 1);
    assert(res == 0);
    assert(memcmp(cipher1, cipher2, SECTOR_SIZE) != 0); // tweak test
    
    // Decrypt sector LBA 1
    res = denyfs_crypt_sector(cipher2, decrypted, 1, key, 0);
    assert(res == 0);
    assert(memcmp(plain, decrypted, SECTOR_SIZE) == 0);
    
    free(plain);
    free(cipher1);
    free(cipher2);
    free(decrypted);
    denyfs_secure_free(key, KEY_SIZE_XTS);
    printf("[+] AES-256-XTS test passed successfully.\n");
}

// Consistency test for KDF Argon2id
void test_kdf_correctness(void) {
    printf("[*] Testing Argon2id KDF...\n");
    
    const char *pass = "extremely_secure_password_123!";
    size_t pass_len = strlen(pass);
    
    uint8_t salt[SALT_SIZE];
    memset(salt, 0xAB, SALT_SIZE);
    
    uint8_t *master_key1 = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *master_key2 = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *master_key3 = denyfs_secure_alloc(KEY_SIZE_GCM);
    assert(master_key1 != NULL && master_key2 != NULL && master_key3 != NULL);
    
    // Derive key 1
    int res = denyfs_derive_master_key(pass, pass_len, salt, master_key1);
    assert(res == 0);
    
    // Derive key 2 (same inputs, must be identical)
    res = denyfs_derive_master_key(pass, pass_len, salt, master_key2);
    assert(res == 0);
    assert(memcmp(master_key1, master_key2, KEY_SIZE_GCM) == 0);
    
    // Derive key 3 (different password, must be different)
    res = denyfs_derive_master_key("different_password", 18, salt, master_key3);
    assert(res == 0);
    assert(memcmp(master_key1, master_key3, KEY_SIZE_GCM) != 0);
    
    // Test HKDF-Expand key derivation from master key
    uint8_t *header_key1 = denyfs_secure_alloc(KEY_SIZE_GCM);
    uint8_t *header_key2 = denyfs_secure_alloc(KEY_SIZE_GCM);
    assert(header_key1 != NULL && header_key2 != NULL);
    
    res = denyfs_derive_header_key(master_key1, header_key1);
    assert(res == 0);
    res = denyfs_derive_header_key(master_key1, header_key2);
    assert(res == 0);
    assert(memcmp(header_key1, header_key2, KEY_SIZE_GCM) == 0);
    
    res = denyfs_derive_header_key(master_key3, header_key2);
    assert(res == 0);
    assert(memcmp(header_key1, header_key2, KEY_SIZE_GCM) != 0);
    
    denyfs_secure_free(master_key1, KEY_SIZE_GCM);
    denyfs_secure_free(master_key2, KEY_SIZE_GCM);
    denyfs_secure_free(master_key3, KEY_SIZE_GCM);
    denyfs_secure_free(header_key1, KEY_SIZE_GCM);
    denyfs_secure_free(header_key2, KEY_SIZE_GCM);
    
    printf("[+] Argon2id and HKDF tests passed successfully.\n");
}

int main(void) {
    if (denyfs_crypto_init() != 0) {
        fprintf(stderr, "[-] Crypto library init failed.\n");
        return 1;
    }
    
    printf("[*] Running Cryptographic Core Tests...\n");
    test_kdf_correctness();
    test_gcm_correctness();
    test_xts_correctness();
    
    denyfs_crypto_cleanup();
    printf("[+] All Cryptographic tests passed successfully.\n");
    return 0;
}
