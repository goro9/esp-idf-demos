//
//  blufi_frame_data_decoder.h
//
//  Created by Kyosuke Kameda on 2020/03/06.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#ifndef blufi_frame_data_decoder_h
#define blufi_frame_data_decoder_h

#include <stdio.h>

#include "blufi_types.h"
#include "blufi_frame.h"

typedef enum {
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_EMPTY = 0,
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_TYPE_MISMATCH,
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_SUBTYPE_MISMATCH,
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_DATA_DIRECTION_MISMATCH,
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_CHECKSUM_MISMATCH,
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_SEQUENCE_NUMBER_SKIPPED,
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_NEED_MORE_FRAME,
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_INVALID_CONTENT_LENGTH,
    BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_READY_TO_DECODE
} blufi_frame_data_decoder_update_result_t;

typedef struct  {
    size_t frame_list_len;
    blufi_frame_t *frame_list;
    blufi_frame_data_decoder_update_result_t state;
} blufi_frame_data_decoder_t;

blufi_frame_data_decoder_t* blufi_frame_data_decoder_new(void);
void blufi_frame_data_decoder_free(blufi_frame_data_decoder_t *decoder);

blufi_frame_data_decoder_update_result_t blufi_frame_data_decoder_update(blufi_frame_data_decoder_t *decoder, const blufi_frame_t *frame);

blufi_data_t *blufi_frame_data_decoder_decode(blufi_frame_data_decoder_t *decoder);

#endif /* blufi_frame_data_decoder_h */
