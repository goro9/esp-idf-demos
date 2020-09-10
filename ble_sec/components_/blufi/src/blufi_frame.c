//
//  blufi_frame.c
//
//  Created by Kyosuke Kameda on 2020/03/03.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#include "blufi_frame.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#define ESP_LOGE(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGW(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGI(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGD(TAG, ...) printf(__VA_ARGS__); puts("");
#define ESP_LOGV(TAG, ...) printf(__VA_ARGS__); puts("");

#else

#include <endian.h>
#include <esp_log.h>

#endif

static const char* TAG = "blufi_frame";

static bool validate_frame(const blufi_frame_t *frame)
{
    // type check
    if (!(frame->type == BLUFI_TYPE_CONTROL || frame->type == BLUFI_TYPE_DATA)) {
        ESP_LOGW(TAG, "invalid frame->type: %d", frame->type);
        return false;
    }
    
    // subtype check
    switch (frame->type) {
        case BLUFI_TYPE_CONTROL:
            switch (frame->subtype) {
                case BLUFI_CONTROL_SUBTYPE_ACK:
                case BLUFI_CONTROL_SUBTYPE_SET_ESP32_TO_THE_SECURITY_MODE:
                case BLUFI_CONTROL_SUBTYPE_SET_THE_OPMODE_OF_WIFI:
                case BLUFI_CONTROL_SUBTYPE_CONNECT_ESP32_TO_THE_AP:
                case BLUFI_CONTROL_SUBTYPE_DISCONNECT_ESP32_FROM_THE_AP:
                case BLUFI_CONTROL_SUBTYPE_TO_GET_THE_INFORMATION_OF_ESP32S_WIFI_MODE_AND_ITS_STATUS:
                case BLUFI_CONTROL_SUBTYPE_DISCONNECT_THE_STA_DEVICE_FROM_THE_SOFT_AP:
                case BLUFI_CONTROL_SUBTYPE_GET_THE_VERSION_INFORMATION:
                case BLUFI_CONTROL_SUBTYPE_DISCONNECT_THE_BLE_GATT_LINK:
                case BLUFI_CONTROL_SUBTYPE_GET_THE_WIFI_LIST:
                    break;
                default:
                    ESP_LOGW(TAG, "invalid frame->subtype: %d", frame->subtype);
                    return false;
                    break;
            }
            break;
        case BLUFI_TYPE_DATA:
            switch (frame->subtype) {
                case BLUFI_DATA_SUBTYPE_SEND_THE_NEGOTIATION_DATA:
                case BLUFI_DATA_SUBTYPE_SEND_THE_BSSID_FOR_STA_MODE:
                case BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_STA_MODE:
                case BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_STA_MODE:
                case BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_SOFT_AP_MODE:
                case BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_SOFT_AP_MODE:
                case BLUFI_DATA_SUBTYPE_SET_THE_MAXIMUM_CONNECTION_NUMBER_FOR_SOFT_AP_MODE:
                case BLUFI_DATA_SUBTYPE_SET_THE_AUTHENTICATION_MODE_FOR_THE_SOFT_AP:
                case BLUFI_DATA_SUBTYPE_SET_THE_CHANNEL_AMOUNT_FOR_SOFT_AP_MODE:
                case BLUFI_DATA_SUBTYPE_USERNAME:
                case BLUFI_DATA_SUBTYPE_CA_CERTIFICATION:
                case BLUFI_DATA_SUBTYPE_CLIENT_CERTIFICATION:
                case BLUFI_DATA_SUBTYPE_SERVER_CERTIFICATION:
                case BLUFI_DATA_SUBTYPE_CLIENT_PRIVATE_KEY:
                case BLUFI_DATA_SUBTYPE_SERVER_PRIVATE_KEY:
                case BLUFI_DATA_SUBTYPE_WIFI_CONNECTIONS_STATE_REPORT:
                case BLUFI_DATA_SUBTYPE_VERSION:
                case BLUFI_DATA_SUBTYPE_WIFI_LIST:
                case BLUFI_DATA_SUBTYPE_REPORT_ERRPR:
                case BLUFI_DATA_SUBTYPE_CUSTOM_DATA:
                    break;
                default:
                    ESP_LOGW(TAG, "invalid frame->subtype: %d", frame->subtype);
                    return false;
                    break;
            }
            break;
    }
        
    // frame_control check
    static const uint8_t max_valid_frame_control = BLUFI_FRAME_CONTROL_FRAME_IS_ENCRYPTED
    | BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM
    | BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION
    | BLUFI_FRAME_CONTROL_OTHER_PERSON_IS_REQUIRED_TO_REPLY_TO_AN_ACK
    | BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS;

    if (max_valid_frame_control < frame->frame_control) {
        ESP_LOGW(TAG, "invalid frame->frame_control: %d", frame->frame_control);
        return false;
    }
    
    // sequence_number check
    // do nothing
    
    // data_length check
    // do nothing
    
    // total_content_length check
    if (0 < (frame->frame_control & BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS)) {
        if (frame->total_content_length == 0) {
            ESP_LOGW(TAG, "invalid frame->total_content_length: %d", frame->total_content_length);
            return false;
        }
        
        if (frame->data_length < 2) {
            ESP_LOGW(TAG, "invalid frame->data_length: %d", frame->data_length);
            return false;
        }
    }
    else if (0 < frame->total_content_length) {
        // BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS が立っていなくて、
        // total_content_length が存在するのはない。
        ESP_LOGW(TAG, "invalid frame->total_content_length: %d", frame->total_content_length);
        return false;
    }
    
    // data_length check
    uint8_t data_length = frame->data_length;
    if (0 < (frame->frame_control & BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS)) {
        data_length -= 2;
    }
    
    if (frame->data.len != data_length) {
        ESP_LOGW(TAG, "invalid frame->data.len: %d", frame->data.len);
        return false;
    }
    
    // check_sum check
    // do nothing
    
    return true;
}

blufi_frame_t* blufi_frame_deep_copy(const blufi_frame_t *src)
{
    assert(src != NULL);
    
    blufi_frame_t *frame = malloc(sizeof(blufi_frame_t));
    assert(frame != NULL);
    memcpy(frame, src, sizeof(blufi_frame_t));
    
    ESP_LOGD(TAG, "src->data.len: %d", src->data.len);
    if (0 < src->data.len){
        frame->data.data = malloc(src->data.len);
        assert(frame->data.data != NULL);
        memcpy(frame->data.data, src->data.data, src->data.len);
    }
    return frame;
}


ssize_t blufi_frame_encode(uint8_t **dst, const blufi_frame_t *frame)
{
    if(!validate_frame(frame)) {
        return -1;
    }

    const size_t len = sizeof(uint8_t)                                                                                    // (type, subtype)
    + sizeof(uint8_t)                                                                                                     // frame_control
    + sizeof(uint8_t)                                                                                                     // sequence_number
    + sizeof(uint8_t)                                                                                                     // data_length
    + frame->data_length                                                                                                  // (total_content_length, data)
    + ((0 < (frame->frame_control & BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM)) ? sizeof(uint16_t) : 0);    // checkSum

    *dst = malloc(len);
    assert(*dst != NULL);
    
    uint8_t *pos = *dst;
    
    *pos = frame->type + (frame->subtype << 2);
    pos++;
    
    *pos = frame->frame_control;
    pos++;
    
    *pos = frame->sequence_number;
    pos++;
    
    *pos = frame->data_length;
    pos++;
    
    if (0 < (frame->frame_control & BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS)) {
        *((uint16_t*)pos) = htole16(frame->total_content_length);
        pos += 2;
    }
    
    memcpy(pos, frame->data.data, frame->data.len);
    pos += frame->data.len;
    
    if (0 < (frame->frame_control & BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM)) {
        *((uint16_t*)pos) = htole16(frame->check_sum);
        pos += 2;
    }
    
    return pos - *dst;
}

bool blufi_frame_decode(blufi_frame_t *dst, const uint8_t *buffer, const size_t buffer_len)
{
    if (buffer_len < 4) {
        return false;
    }
    
    uint8_t *pos = (uint8_t*)buffer;

    const uint8_t type_and_subtype = *(pos);
    pos++;
    
    const blufi_type_t type = type_and_subtype & 0x1;
    const uint8_t subtype = type_and_subtype >> 2;

    const uint8_t frame_control = *(pos);
    pos++;
    
    const uint8_t sequence_number = *(pos);
    pos++;
    
    const uint8_t data_length = *(pos);
    pos++;

    uint16_t total_content_length = 0;
    if (0 < (frame_control & BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS)) {
        if (buffer + buffer_len < pos + 2) {
            return false;
        }
        total_content_length = le16toh(*(uint16_t*)pos);
        pos += 2;
    }
    
    const uint8_t *end_pos = pos + data_length - (total_content_length != 0 ? 2 : 0);
    if (end_pos < pos) {
        return false;
    }
    
    uint8_t *data = NULL;
    const uint8_t len = end_pos - pos;
    if (len != 0) {
        data = malloc(sizeof(uint8_t) * len);
        assert(data != NULL);
        memcpy(data, pos, len);
        pos += len;
    }
    
    uint16_t check_sum = 0;
    if (0 < (frame_control & BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM)) {
        if (buffer + buffer_len < pos + 2) {
            free(data);
            return false;
        }
        check_sum = le16toh(*(uint16_t*)pos);
        pos += 2;
    }
    
    if (pos != buffer + buffer_len) {
        free(data);
        return false;
    }
    
    dst->type = type;
    dst->subtype = subtype;
    dst->frame_control = frame_control;
    dst->sequence_number = sequence_number;
    dst->data_length = data_length;
    dst->total_content_length = total_content_length;
    dst->data.data = data;
    dst->data.len = len;
    dst->check_sum = check_sum;
    
    if (!validate_frame(dst)) {
        free(data);
        return false;
    }
    return true;
}
