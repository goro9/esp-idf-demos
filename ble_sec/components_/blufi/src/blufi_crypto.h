//
//  blufi_crypto.h
//
//  Created by Kyosuke Kameda on 2020/03/12.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#ifndef blufi_crypto_h
#define blufi_crypto_h

#include <stdint.h>

int blufi_crypto_create_diffie_hellman_key_pair(
    const char *prime,
    const char *generator,
    uint8_t out_private_key[128],
    uint8_t out_public_key[128]);

int blufi_crypto_generate_secret_key(
    const char *hex_prime,
    const uint8_t *private_key,
    const uint8_t *app_public_key,
    uint8_t out_secret_key[128]);

void blufi_crypto_generate_iv(uint8_t dst[16], uint8_t sequence_number);

int blufi_crypto_aes_decrypt(uint8_t *in_out_crypto_data, uint8_t data_len, uint8_t iv[16], uint8_t secret_key[128]);

uint16_t blufi_crypto_calc_checksum(uint8_t seq_num, uint8_t data_len, const uint8_t *data);


#endif /* blufi_crypto_h */
