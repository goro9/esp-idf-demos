//
//  blufi_session.c
//
//  Created by Kyosuke Kameda on 2020/03/09.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#include "blufi_session.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "blufi_frame.h"
#include "blufi_frame_data_decoder.h"
#include "blufi_frame_data_encoder.h"
#include "blufi_crypto.h"

#ifdef __APPLE__

#define ESP_LOGE(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGW(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGI(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGD(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGV(TAG, ...) printf(__VA_ARGS__); puts("");

#else

#include <esp_log.h>

#endif

static const char* TAG = "blufi_session";

blufi_session_t *blufi_session_new(blufi_session_writer writer)
{
    assert(writer != NULL);
    
    blufi_session_t *session = calloc(1, sizeof(blufi_session_t));
    assert(session != NULL);
    
    session->writer = writer;
    return session;
}

void blufi_session_free(blufi_session_t *session)
{
    if (session == NULL) {
        return;
    }
        
    if (session->frame_data_decoder) {
        blufi_frame_data_decoder_free(session->frame_data_decoder);
        session->frame_data_decoder = NULL;
    }

    session->writer = NULL;
    free(session);
}

int blufi_session_update(blufi_session_t *session, const uint8_t *buffer, uint16_t buffer_len)
{
    assert(session != NULL);
    
    blufi_frame_t frame;
    bool r = blufi_frame_decode(&frame, buffer, buffer_len);
    if (!r) {
        ESP_LOGW(TAG, "invalid buffer");
        return -1;
    }
    
    // decrypte
    if (0 < (frame.frame_control & BLUFI_FRAME_CONTROL_FRAME_IS_ENCRYPTED)) {
        uint8_t iv[16] = {0};
        blufi_crypto_generate_iv(iv, frame.sequence_number);
        int r = blufi_crypto_aes_decrypt(frame.data.data, frame.data.len, iv, session->secret_key);
    }

    if (frame.sequence_number != session->app_sequence_number) {
        ESP_LOGW(TAG, "sequence_number skipped");
        return -1;
    }

    if (0 < (frame.frame_control & BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION)) {
        ESP_LOGW(TAG, "data direction is invalid");
        return -1;
    }

    if (!session->frame_data_decoder) {
        session->frame_data_decoder = blufi_frame_data_decoder_new();
    }
    
    blufi_frame_data_decoder_update_result_t res;
    res = blufi_frame_data_decoder_update(session->frame_data_decoder, &frame);
    
    switch (res) {
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_EMPTY:                      // fall through
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_TYPE_MISMATCH:              // fall through
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_SUBTYPE_MISMATCH:           // fall through
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_DATA_DIRECTION_MISMATCH:    // fall through
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_CHECKSUM_MISMATCH:          // fall through
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_SEQUENCE_NUMBER_SKIPPED:    // fall through
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_INVALID_CONTENT_LENGTH:
            break;
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_NEED_MORE_FRAME:            // fall through
        case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_READY_TO_DECODE:
            session->app_sequence_number++;
            break;
        default:
            assert(false);
            break;
    }
    return res;
}

blufi_data_t* blufi_session_decode(const blufi_session_t *session)
{
    if (session->frame_data_decoder == NULL) {
        ESP_LOGW(TAG, "session->frame_data_decoder is not initialized.");
        return NULL;
    }
    return blufi_frame_data_decoder_decode(session->frame_data_decoder);
}

int blufi_session_post_ack(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle)
{
    blufi_frame_t *frame_list;

    const uint8_t data[] = {session->app_sequence_number - 1};    // 直前に送ったもの
    ssize_t frame_list_len
    = blufi_frame_data_encoder_encode(&frame_list,
                                      BLUFI_TYPE_CONTROL,
                                      BLUFI_CONTROL_SUBTYPE_ACK,
                                      BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION,
                                      session->esp32_sequence_number,
                                      data,
                                      sizeof(data)/sizeof(data[0]),
                                      session->mtu);
    assert(0 < frame_list_len);
    assert(frame_list != NULL);

    int r = session->writer(session, conn_handle, attr_handle, frame_list, frame_list_len);
    if (r != 0) {
        ESP_LOGW(TAG, "session->writer fail:%d", r);
    }

    for (int i=0; i<frame_list_len; ++i) {
        free(frame_list[i].data.data);
    }
    free(frame_list);
    return r;
}

int blufi_session_post_send_the_negotiation_data(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle, uint8_t *public_key, uint16_t public_key_len)
{
    blufi_frame_t *frame_list;
    ssize_t frame_list_len
    = blufi_frame_data_encoder_encode(&frame_list,
                                      BLUFI_TYPE_DATA,
                                      BLUFI_DATA_SUBTYPE_SEND_THE_NEGOTIATION_DATA,
                                      BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION,
                                      session->esp32_sequence_number,
                                      public_key,
                                      public_key_len,
                                      session->mtu);
    assert(0 < frame_list_len);
    assert(frame_list != NULL);
    
    int r = session->writer(session, conn_handle, attr_handle, frame_list, frame_list_len);
    if (r != 0) {
        ESP_LOGW(TAG, "session->writer fail:%d", r);
    }
    else {
        session->negotiated = true;
    }

    for (int i=0; i<frame_list_len; ++i) {
        free(frame_list[i].data.data);
    }
    free(frame_list);
    return r;
}

int blufi_session_post_custom_data(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle, uint8_t *data, uint16_t data_len)
{
    if (!session->negotiated){
        ESP_LOGE(TAG, "need security negotiation first");
        return -1;
    }

    blufi_frame_t *frame_list;
    ssize_t frame_list_len
    = blufi_frame_data_encoder_encode(&frame_list,
                                      BLUFI_TYPE_DATA,
                                      BLUFI_DATA_SUBTYPE_CUSTOM_DATA,
                                      BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION,
                                      session->esp32_sequence_number,
                                      data,
                                      data_len,
                                      session->mtu);
    assert(0 < frame_list_len);
    assert(frame_list != NULL);
    
    int r = session->writer(session, conn_handle, attr_handle, frame_list, frame_list_len);
    if (r != 0) {
        ESP_LOGW(TAG, "session->writer fail:%d", r);
    }

    for (int i=0; i<frame_list_len; ++i) {
        free(frame_list[i].data.data);
    }
    free(frame_list);
    return r;
}

int blufi_session_post_wifi_list(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle, const wifi_ap_record_t *aps, uint16_t aps_len)
{
    if (!session->negotiated){
        ESP_LOGE(TAG, "need security negotiation first");
        return -1;
    }

    // 以下のデータを作る
    // struct {
    //     uint8_t length;
    //     uint8_t rssi;
    //     char[length - 1] ssid;   // not null term
    // }

    // add dummy ap
    // https://github.com/natureglobal/remo-e-project/issues/132#issuecomment-536940191
    const char not_exist_ap[32] = "not exist ap";
    size_t not_exist_ap_len = strlen(not_exist_ap);

    uint16_t len = 1      // sizeof(length)
                   + 1    // sizeof(rssi)
                   + not_exist_ap_len;
    
    for (int i = 0; i < aps_len; i++) {
        len++;    // length
        len++;    // rssi
        len += strlen((char*)aps[i].ssid);
    }

    // dummy を出す
    uint8_t *buf = malloc(sizeof(uint8_t) * len);
    assert(buf != NULL);
    uint8_t *pos = buf;

    // length
    *pos = (uint8_t)not_exist_ap_len + 1;
    pos++;

    // rssi
    *pos = UINT8_MAX;
    pos++;

    // ssid
    memcpy(pos, not_exist_ap, not_exist_ap_len);
    pos += not_exist_ap_len;

    for (int i = 0; i < aps_len; i++) {
        // https://github.com/espressif/esp-idf/blob/1e95cf3111a9c95b7debc8be84175147bf7a80c4/components/esp_wifi/include/esp_wifi_types.h#L157
        // 長くても 32
        size_t ssid_len = strlen((char*)aps[i].ssid);
        assert(ssid_len <= 32);

        // length
        *pos = (uint8_t)ssid_len + 1;
        pos++;

        // rssi
        *pos = aps[i].rssi;
        pos++;

        // ssid
        memcpy(pos, aps[i].ssid, ssid_len);
        pos += ssid_len;
    }

    blufi_frame_t *frame_list;
    ssize_t frame_list_len
    = blufi_frame_data_encoder_encode(&frame_list,
                                      BLUFI_TYPE_DATA,
                                      BLUFI_DATA_SUBTYPE_WIFI_LIST,
                                      BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION,
                                      session->esp32_sequence_number,
                                      buf,
                                      len,
                                      session->mtu);
    assert(0 < frame_list_len);
    assert(frame_list != NULL);
    
    int r = session->writer(session, conn_handle, attr_handle, frame_list, frame_list_len);
    if (r != 0) {
        ESP_LOGW(TAG, "session->writer fail:%d", r);
    }

    for (int i=0; i<frame_list_len; ++i) {
        free(frame_list[i].data.data);
    }
    free(frame_list);
    return r;
}
