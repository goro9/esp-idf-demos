//
//  blufi_crypto.c
//
//  Created by Kyosuke Kameda on 2020/03/12.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#include "blufi_crypto.h"

#include <string.h>

// mac 環境で動かしたい場合は `brew install mbedtls` を行い mbedtls を導入し、
// header search path や libmbedcrypto へのリンクを適切にすること
#include <mbedtls/bignum.h>
#include <mbedtls/config.h>
#include <mbedtls/md5.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#ifdef __APPLE__

#include <stdio.h>
#include <stdlib.h>

#define ESP_LOGE(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGW(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGI(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGD(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGV(TAG, ...) printf(__VA_ARGS__); puts("");

#else

#include <esp_log.h>

#endif

static const char* TAG = "blufi_crypto";

static const uint16_t crc_table[] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, 0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823, 0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70, 0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, 0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d, 0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a, 0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static uint16_t CRCCCITT(uint32_t crc, uint8_t *data, size_t len)
{
    crc = (~crc) & 0xffff;
    for (int i=0; i<len; ++i){
        crc = crc_table[(crc >> 8) ^ (data[i] & 0xff)] ^ (crc << 8);
        crc &= 0xffff;
    }
    return (~crc) & 0xffff;
}

int blufi_crypto_create_diffie_hellman_key_pair(
    const char *prime,
    const char *generator,
    uint8_t out_private_key[128],
    uint8_t out_public_key[128])
{
    int exit_code;
    int r;
    mbedtls_mpi p;
    mbedtls_mpi g;
    mbedtls_mpi private_key;
    mbedtls_mpi public_key;

    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&g);
    mbedtls_mpi_init(&private_key);
    mbedtls_mpi_init(&public_key);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed error, error code = 0x%x", r);
        exit_code = -1;
        goto cleanup;
    }

    r = mbedtls_mpi_read_string(&p, 16, prime);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_read_string prime error, error code = 0x%x", r);
        exit_code = -1;
        goto cleanup;
    }

    r = mbedtls_mpi_read_string(&g, 10, generator);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_read_string generator error, error code = 0x%x", r);
        exit_code = -1;
        goto cleanup;
    }

    // calc private key
    do {
        r = mbedtls_mpi_fill_random(&private_key, 128, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (r != 0) {
            ESP_LOGE(TAG, "mbedtls_mpi_fill_random error, error code = %x", r);
            exit_code = -1;
            goto cleanup;
        }

        if (mbedtls_mpi_cmp_mpi(&p, &private_key) == 1) {
            break;
        }
        mbedtls_mpi_free(&private_key);
        mbedtls_mpi_init(&private_key);
    } while (1);

    r = mbedtls_mpi_write_binary(&private_key, out_private_key, 128);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_write_binary private_key error, error code = %x", r);
        exit_code = -1;
        goto cleanup;
    }

    // calc public key
    r = mbedtls_mpi_exp_mod(&public_key, &g, &private_key, &p, NULL);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_exp_mod error, error code = %x", r);
        exit_code = -1;
        goto cleanup;
    }

    r = mbedtls_mpi_write_binary(&public_key, out_public_key, 128);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_write_binary public_key error, error code = %x", r);
        exit_code = -1;
        goto cleanup;
    }

    exit_code = 0;

cleanup:
    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&private_key);
    mbedtls_mpi_free(&public_key);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return exit_code;
}

int blufi_crypto_generate_secret_key(
    const char *hex_prime,
    const uint8_t *private_key,
    const uint8_t *app_public_key,
    uint8_t out_secret_key[128])
{
    int exit_code;
    int r;
    mbedtls_mpi bignum_p;
    mbedtls_mpi bignum_private_key;
    mbedtls_mpi bignum_app_public_key;
    mbedtls_mpi bignum_secret_key;

    mbedtls_mpi_init(&bignum_p);
    mbedtls_mpi_init(&bignum_private_key);
    mbedtls_mpi_init(&bignum_app_public_key);
    mbedtls_mpi_init(&bignum_secret_key);

    r = mbedtls_mpi_read_string(&bignum_p, 16, hex_prime);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_read_binary prime error, error code = 0x%x", r);
        exit_code = -1;
        goto cleanup;
    }

    r = mbedtls_mpi_read_binary(&bignum_private_key, private_key, 128);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_read_binary private_key error, error code = 0x%x", r);
        exit_code = -1;
        goto cleanup;
    }

    r = mbedtls_mpi_read_binary(&bignum_app_public_key, app_public_key, 128);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_read_binary private_key error, error code = 0x%x", r);
        exit_code = -1;
        goto cleanup;
    }

    // calc secret key
    r = mbedtls_mpi_exp_mod(&bignum_secret_key, &bignum_app_public_key, &bignum_private_key, &bignum_p, NULL);

    r = mbedtls_mpi_write_binary(&bignum_secret_key, out_secret_key, 128);
    if (r != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_write_binary secret_key error, error code = %x", r);
        exit_code = -1;
        goto cleanup;
    }
    
    exit_code = 0;

cleanup:
    mbedtls_mpi_free(&bignum_p);
    mbedtls_mpi_free(&bignum_private_key);
    mbedtls_mpi_free(&bignum_app_public_key);
    mbedtls_mpi_free(&bignum_secret_key);

    return exit_code;
}

void blufi_crypto_generate_iv(uint8_t dst[16], uint8_t sequence_number)
{
    memset(dst, 0, 16);
    dst[0] = sequence_number;
}

int blufi_crypto_aes_decrypt(uint8_t *in_out_crypto_data, uint8_t data_len, uint8_t iv[16], uint8_t secret_key[128])
{
    int r;
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    uint8_t psk[16];
    mbedtls_md5(secret_key, 128, psk);
    r = mbedtls_aes_setkey_dec(&ctx, psk, 128);
    if (r != 0) {
        ESP_LOGD(TAG, "mbedtls_aes_setkey_dec fail: %d", r);
    }

    size_t iv_offset = 0;
    r = mbedtls_aes_crypt_cfb128(
        &ctx,
        MBEDTLS_AES_DECRYPT,
        data_len,
        &iv_offset,
        iv,
        in_out_crypto_data,
        in_out_crypto_data);

    mbedtls_aes_free(&ctx);
    if (r != 0) {
        ESP_LOGD(TAG, "mbedtls_aes_crypt_cfb128 fail: %d", r);
    }
    return r;
}

uint16_t blufi_crypto_calc_checksum(uint8_t seq_num, uint8_t data_len, const uint8_t *data)
{
    size_t len = sizeof(seq_num) + sizeof(data_len) + data_len;
    uint8_t *d = malloc(sizeof(uint8_t) * len);
    d[0] = seq_num;
    d[1] = data_len;
    memcpy(&d[2], data, data_len);
    return CRCCCITT(0, d, len);    
}
