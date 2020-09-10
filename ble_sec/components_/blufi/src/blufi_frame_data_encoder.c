//
//  blufi_frame_data_encoder.c
//
//  Created by Kyosuke Kameda on 2020/03/07.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#include "blufi_frame_data_encoder.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "blufi_frame.h"
#include "blufi_crypto.h"

ssize_t blufi_frame_data_encoder_encode(blufi_frame_t **dst_frame_list,
                                        blufi_type_t type,
                                        uint8_t subtype,
                                        uint8_t frame_control,
                                        uint8_t sequence_number,
                                        const uint8_t *data,
                                        uint16_t data_len,
                                        uint8_t mtu)
{
    static const uint8_t BLUFI_FRAME_MIN_SIZE = 6;
    const int16_t len = mtu - BLUFI_FRAME_MIN_SIZE;
    if (len < BLUFI_FRAME_MIN_SIZE) {
        return -1;
    }
     
    int16_t total_content_len = data_len;
    int8_t frame_list_len = 0;
    do {
        frame_list_len++;
        int16_t fragment_data_length = 0;
        if (len < total_content_len) {
            fragment_data_length = len;
        }
        else {
            fragment_data_length = total_content_len;
        }
        
        total_content_len -= fragment_data_length;
    } while ( 0 < total_content_len);
    assert(total_content_len == 0);

    *dst_frame_list = malloc(sizeof(blufi_frame_t) * frame_list_len);
    assert(*dst_frame_list != NULL);
    
    // BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS はこの encode 処理で自動でつけるから
    // 引数に含まれていたら除外する
    static const uint8_t MASK = (BLUFI_FRAME_CONTROL_FRAME_IS_ENCRYPTED
                                 | BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM
                                 | BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION
                                 | BLUFI_FRAME_CONTROL_OTHER_PERSON_IS_REQUIRED_TO_REPLY_TO_AN_ACK);

    const uint8_t flterd_frame_control = frame_control & MASK;
    
    total_content_len = data_len;
    uint16_t pos = 0;
    uint8_t index = 0;
    do {
        uint8_t fc;
        const uint8_t *fragment_data_data;
        uint8_t fragment_data_data_len;
        int16_t fragment_data_length = 0;
        if (len < total_content_len) {
            fc = flterd_frame_control | BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS;
            fragment_data_data = data + pos;
            fragment_data_data_len = len 
                                     - sizeof(uint16_t);    // sizeof(blufi_frame_s.total_content_length)
            fragment_data_length = len;
        }
        else {
            fc = flterd_frame_control;
            fragment_data_data = data + pos;
            fragment_data_data_len = total_content_len;
            fragment_data_length = fragment_data_data_len;
        }
        
        uint16_t check_sum = 0;
        if (0 < (fc & BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM)) {
            check_sum = blufi_crypto_calc_checksum(sequence_number, fragment_data_data_len, fragment_data_data);
        }

        uint8_t *d = malloc(sizeof(uint8_t) * fragment_data_data_len);
        assert(d != NULL);
        memcpy(d, fragment_data_data, fragment_data_data_len);
        
        const blufi_frame_t frame = {
            .type = type,
            .subtype = subtype,
            .frame_control = fc,
            .sequence_number = sequence_number,
            .data_length = fragment_data_length,
            .total_content_length = (total_content_len == fragment_data_length ? 0 : total_content_len),
            .data = {
                .data = d,
                .len = fragment_data_data_len,
            },
            .check_sum = check_sum,
        };
        memcpy(*dst_frame_list + index, &frame, sizeof(blufi_frame_t));
        
        sequence_number++;
        index++;

        total_content_len -= fragment_data_data_len;
        pos += fragment_data_data_len;
    } while ( 0 < total_content_len);
    assert(total_content_len == 0);
    
    return frame_list_len;
}
