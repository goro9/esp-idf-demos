//
//  blufi_frame.h
//
//  Created by Kyosuke Kameda on 2020/03/03.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#ifndef blufi_frame_h
#define blufi_frame_h

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "blufi_types.h"

typedef struct blufi_frame_data_s blufi_frame_data_t;
typedef struct blufi_frame_s blufi_frame_t;

struct blufi_frame_data_s {
    uint8_t *data;
    uint8_t len;
};

struct blufi_frame_s {
    blufi_type_t type;
    uint8_t subtype;
    uint8_t frame_control;
    uint8_t sequence_number;
    uint8_t data_length;
    uint16_t total_content_length;
    blufi_frame_data_t data;
    uint16_t check_sum;
};

blufi_frame_t* blufi_frame_deep_copy(const blufi_frame_t *src);

ssize_t blufi_frame_encode(uint8_t **dst, const blufi_frame_t *frame);
bool blufi_frame_decode(blufi_frame_t *dst, const uint8_t *buffer, const size_t buffer_len);

#endif /* blufi_frame_h */
