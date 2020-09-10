//
//  blufi_session.h
//
//  Created by Kyosuke Kameda on 2020/03/09.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#ifndef blufi_session_h
#define blufi_session_h

#include <stdint.h>

#ifdef __APPLE__

// https://github.com/espressif/esp-idf/blob/1e95cf3111a9c95b7debc8be84175147bf7a80c4/components/esp_wifi/include/esp_wifi_types.h#L154-L172
// から最小の
typedef struct {
    uint8_t ssid[33];
    int8_t  rssi;
} wifi_ap_record_t;

#else

#include <esp_wifi.h>

#endif


#include "blufi_frame_data_decoder.h"

typedef struct blufi_session_s blufi_session_t;

typedef int (*blufi_session_writer)(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle, const blufi_frame_t *frame_list, size_t frame_list_len);

struct blufi_session_s {
    uint8_t mtu;
    uint8_t app_sequence_number;
    uint8_t esp32_sequence_number;
    
    uint8_t private_key[128];
    uint8_t public_key[128];
    uint8_t secret_key[128];
    bool negotiated;

    blufi_frame_data_decoder_t *frame_data_decoder;
    blufi_session_writer writer;
};

blufi_session_t *blufi_session_new(blufi_session_writer writer);
void blufi_session_free(blufi_session_t *session);

int blufi_session_update(blufi_session_t *session, const uint8_t *buffer, uint16_t buffer_len);
blufi_data_t* blufi_session_decode(const blufi_session_t *session);

// control
int blufi_session_post_ack(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle);

// data
int blufi_session_post_send_the_negotiation_data(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle, uint8_t *public_key, uint16_t public_key_len);
int blufi_session_post_custom_data(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle, uint8_t *data, uint16_t data_len);
int blufi_session_post_wifi_list(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle, const wifi_ap_record_t *aps, uint16_t aps_len);


#endif /* blufi_session_h */
