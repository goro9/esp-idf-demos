//
//  blufi_frame_data_encoder.h
//
//  Created by Kyosuke Kameda on 2020/03/07.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#ifndef blufi_frame_data_encoder_h
#define blufi_frame_data_encoder_h

#include <stdio.h>
#include <stdint.h>

#include "blufi_types.h"
#include "blufi_frame.h"

ssize_t blufi_frame_data_encoder_encode(blufi_frame_t **dst_frame_list,
                                        blufi_type_t type,
                                        uint8_t subtype,
                                        uint8_t frame_control,
                                        uint8_t sequence_number,
                                        const uint8_t *data,
                                        uint16_t data_len,
                                        uint8_t mtu);

#endif /* blufi_frame_data_encoder_h */
