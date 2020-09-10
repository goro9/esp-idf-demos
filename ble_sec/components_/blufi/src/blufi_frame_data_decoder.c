//
//  blufi_frame_data_decoder.c
//
//  Created by Kyosuke Kameda on 2020/03/06.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#include "blufi_frame_data_decoder.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "blufi_crypto.h"

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

#define ESP_LOG_BUFFER_HEXDUMP(TAG, d, len, level)

#else

#include <endian.h>
#include <esp_log.h>

#endif

static const char* TAG = "blufi_frame_data_decoder";

static blufi_data_t *decode_ack(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    assert(data != NULL);
    if (data_len != 1) {
        return NULL;
    }
    
    blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_ACK, frame_control);
    r->ack.request_sequence = data[0];
    return r;
}

static blufi_data_t *decode_send_the_negotiation_data(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    assert(data != NULL);

    ESP_LOG_BUFFER_HEXDUMP(TAG, data, data_len, ESP_LOG_DEBUG);

    uint8_t *pos = (uint8_t*)data;
    switch (*pos) {
        case 0:
        {
            blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_SEND_THE_NEGOTIATION_DATA0, frame_control);

            pos++;
            
            const uint16_t pkg_len = be16toh(*((uint16_t*)pos));
            pos += 2;
            assert((pos - data) == data_len);

            r->send_the_negotiation_data0.pkg_len = pkg_len;
            return r;
        }
        case 1:{
            blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_SEND_THE_NEGOTIATION_DATA1, frame_control);

            pos++;
            
            const uint16_t prime_len = be16toh(*((uint16_t*)pos));
            pos += 2;
            
            uint8_t *prime = malloc(sizeof(uint8_t) * prime_len);
            assert(prime != NULL);
            memcpy(prime, pos, prime_len);
            pos += prime_len;
            
            const uint16_t generator_len = be16toh(*((uint16_t*)pos));
            pos += 2;

            uint8_t *generator = malloc(sizeof(uint8_t) * generator_len);
            assert(generator != NULL);
            memcpy(generator, pos, generator_len);
            pos += generator_len;

            const uint16_t pubkey_len = be16toh(*((uint16_t*)pos));
            pos += 2;

            uint8_t *pubkey = malloc(sizeof(uint8_t) * pubkey_len);
            assert(pubkey != NULL);
            memcpy(pubkey, pos, pubkey_len);
            pos += pubkey_len;

            assert((pos - data) == data_len);

            r->send_the_negotiation_data1.prime_len = prime_len;
            r->send_the_negotiation_data1.prime = prime;
            r->send_the_negotiation_data1.generator_len = generator_len;
            r->send_the_negotiation_data1.generator = generator;
            r->send_the_negotiation_data1.pubkey_len = pubkey_len;
            r->send_the_negotiation_data1.pubkey = pubkey;
            return r;
        }
            break;
        default:
            assert(false);
            break;
    }
    return NULL;
}

static blufi_data_t *decode_set_esp32_to_the_security_mode(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    assert(data != NULL);
    if (data_len != 1) {
        return NULL;
    }

    blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_SET_ESP32_TO_THE_SECURITY_MODE, frame_control);
    r->set_esp32_to_the_security_mode.check_sum_enable = data[0] != 0;
    return r;
}

static blufi_data_t *decode_set_the_opmode_of_wifi(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    assert(data != NULL);
    if (data_len != 1) {
        return NULL;
    }

    blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_SET_THE_OPMODE_OF_WIFI_DATA, frame_control);
    r->set_the_opmode_of_wifi_data.opmode_of_wifi = data[0];
    return r;
}

static blufi_data_t *decode_custom_data(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    assert(data != NULL);

    blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_CUSTOM_DATA, frame_control);
    r->custom_data.data = malloc(sizeof(uint8_t) * data_len);
    assert(r->custom_data.data != NULL);
    memcpy(r->custom_data.data, data, data_len);
    r->custom_data.data_len = data_len;
    return r;
}

static blufi_data_t *decode_get_the_wifi_list(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_GET_THE_WIFI_LIST, frame_control);
    return r;
}

static blufi_data_t *decode_send_the_ssid_for_sta_mode(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_SEND_THE_SSID_FOR_STA_MODE_DATA, frame_control);
    r->send_the_ssid_for_sta_mode_data.ssid = malloc(sizeof(char) * data_len + 1);
    assert(r->send_the_ssid_for_sta_mode_data.ssid != NULL);
    memcpy(r->send_the_ssid_for_sta_mode_data.ssid, data, data_len);
    r->send_the_ssid_for_sta_mode_data.ssid[data_len] = 0;

    ESP_LOGD(TAG, "r->send_the_ssid_for_sta_mode_data.ssid: %s", r->send_the_ssid_for_sta_mode_data.ssid);

    return r;
}

static blufi_data_t *decode_send_the_password_for_sta_mode(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_SEND_THE_PASSWORD_FOR_STA_MODE_DATA, frame_control);
    r->send_the_password_for_sta_mode_data.password = malloc(sizeof(char) * data_len + 1);
    assert(r->send_the_password_for_sta_mode_data.password != NULL);
    memcpy(r->send_the_password_for_sta_mode_data.password, data, data_len);
    r->send_the_password_for_sta_mode_data.password[data_len] = 0;

    ESP_LOGD(TAG, "r->send_the_password_for_sta_mode_data.password: %s", r->send_the_password_for_sta_mode_data.password);

    return r;
}

static blufi_data_t *decode_connect_esp32_to_the_ap(uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    blufi_data_t *r = blufi_data_new(BLUFI_DATA_TYPE_CONNECT_ESP32_TO_THE_AP, frame_control);
    return r;
}

static blufi_data_t* decode_data(blufi_type_t type, uint8_t subtype, uint8_t frame_control, const uint8_t *data, uint16_t data_len)
{
    ESP_LOGD(TAG, "%s:%d", __FUNCTION__, __LINE__);

    // assert(data != NULL);    // データがないのもある！！

    ESP_LOGD(TAG, "type: %d, subtype: %d", type, subtype);
    
    switch (type) {
        case BLUFI_TYPE_CONTROL:
            switch (subtype) {
                case BLUFI_CONTROL_SUBTYPE_ACK:
                    return decode_ack(frame_control, data, data_len);
                case BLUFI_CONTROL_SUBTYPE_SET_ESP32_TO_THE_SECURITY_MODE:
                    return decode_set_esp32_to_the_security_mode(frame_control, data, data_len);
                case BLUFI_CONTROL_SUBTYPE_SET_THE_OPMODE_OF_WIFI:
                    return decode_set_the_opmode_of_wifi(frame_control, data, data_len);
                case BLUFI_CONTROL_SUBTYPE_CONNECT_ESP32_TO_THE_AP:
                    return decode_connect_esp32_to_the_ap(frame_control, data, data_len);
                case BLUFI_CONTROL_SUBTYPE_DISCONNECT_ESP32_FROM_THE_AP:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_CONTROL_SUBTYPE_TO_GET_THE_INFORMATION_OF_ESP32S_WIFI_MODE_AND_ITS_STATUS:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_CONTROL_SUBTYPE_DISCONNECT_THE_STA_DEVICE_FROM_THE_SOFT_AP:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_CONTROL_SUBTYPE_GET_THE_VERSION_INFORMATION:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_CONTROL_SUBTYPE_DISCONNECT_THE_BLE_GATT_LINK:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_CONTROL_SUBTYPE_GET_THE_WIFI_LIST:
                    return decode_get_the_wifi_list(frame_control, data, data_len);
                default:
                    return NULL;
                    break;
            }
            break;
        case BLUFI_TYPE_DATA:
            switch (subtype) {
                case BLUFI_DATA_SUBTYPE_SEND_THE_NEGOTIATION_DATA:
                    return decode_send_the_negotiation_data(frame_control, data, data_len);
                case BLUFI_DATA_SUBTYPE_SEND_THE_BSSID_FOR_STA_MODE:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_STA_MODE:
                    return decode_send_the_ssid_for_sta_mode(frame_control, data, data_len);
                case BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_STA_MODE:
                    return decode_send_the_password_for_sta_mode(frame_control, data, data_len);
                case BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_SOFT_AP_MODE:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_SOFT_AP_MODE:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_SET_THE_MAXIMUM_CONNECTION_NUMBER_FOR_SOFT_AP_MODE:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_SET_THE_AUTHENTICATION_MODE_FOR_THE_SOFT_AP:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_SET_THE_CHANNEL_AMOUNT_FOR_SOFT_AP_MODE:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_USERNAME:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_CA_CERTIFICATION:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_CLIENT_CERTIFICATION:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_SERVER_CERTIFICATION:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_CLIENT_PRIVATE_KEY:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_SERVER_PRIVATE_KEY:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_WIFI_CONNECTIONS_STATE_REPORT:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_VERSION:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_WIFI_LIST:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_REPORT_ERRPR:
                    ESP_LOGW(TAG, "not supported. type: %d, subtype: %d", type, subtype);
                    return NULL;
                case BLUFI_DATA_SUBTYPE_CUSTOM_DATA:
                    return decode_custom_data(frame_control, data, data_len);
                default:
                    return NULL;
            }

            break;
        default:
            break;
    }
    
    return NULL;
}

blufi_frame_data_decoder_t* blufi_frame_data_decoder_new(void)
{
    blufi_frame_data_decoder_t *decoder = malloc(sizeof(blufi_frame_data_decoder_t));
    assert(decoder != NULL);
    
    decoder->frame_list_len = 0;
    decoder->frame_list = NULL;
    decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_EMPTY;
    return decoder;
}

void blufi_frame_data_decoder_free(blufi_frame_data_decoder_t *decoder)
{
    if (decoder == NULL) {
        return;
    }
    
    if (decoder->frame_list) {
        for (int i=0; i<decoder->frame_list_len; ++i) {
            free(decoder->frame_list[i].data.data);
        }
        free(decoder->frame_list);
        decoder->frame_list = NULL;
    }
    free(decoder);
}

blufi_frame_data_decoder_update_result_t blufi_frame_data_decoder_update(blufi_frame_data_decoder_t *decoder, const blufi_frame_t *frame)
{
    assert(decoder != NULL);
    assert(frame != NULL);
    
    if (0 < decoder->frame_list_len){
        // check type/subtype
        blufi_frame_t head = decoder->frame_list[0];
        if (head.type != frame->type) {
            decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_TYPE_MISMATCH;
            return decoder->state;
        }
        
        if (head.subtype != frame->subtype) {
            decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_SUBTYPE_MISMATCH;
            return decoder->state;
        }

        // check data direction
        const uint8_t head_direction = head.frame_control & BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION;
        const uint8_t frame_direction = frame->frame_control & BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION;
        if (head_direction != frame_direction) {
            decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_DATA_DIRECTION_MISMATCH;
            return decoder->state;
        }
    }

    // check check sum
    const uint8_t frame_checksum = frame->frame_control & BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM;
    if (0 < frame_checksum) {
        uint16_t checksum = blufi_crypto_calc_checksum(frame->sequence_number, frame->data.len, frame->data.data);
        if (frame->check_sum != checksum) {
            decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_CHECKSUM_MISMATCH;
            return decoder->state;
        }
    }

    blufi_frame_t *frame_list = realloc(decoder->frame_list, sizeof(blufi_frame_t) * (decoder->frame_list_len + 1));
    assert(frame_list != NULL);

    blufi_frame_t *copied_frame = blufi_frame_deep_copy(frame);
    memcpy(&frame_list[decoder->frame_list_len], copied_frame, sizeof(blufi_frame_t));
    free(copied_frame);    // copied_frame->data.data は frame_list の開放時に一緒に開放されるので、ここでやってはダメ！！
    copied_frame = NULL;

    decoder->frame_list = frame_list;
    decoder->frame_list_len++;

    // sort
    for (int x=0; x<decoder->frame_list_len - 1; ++x) {
        for (int i=x; i<decoder->frame_list_len - 1; ++i) {
            blufi_frame_t a = decoder->frame_list[i];
            blufi_frame_t b = decoder->frame_list[i+1];
            
            if (b.sequence_number < a.sequence_number) {
                memcpy(&decoder->frame_list[i+1], &a, sizeof(blufi_frame_t));
                memcpy(&decoder->frame_list[i], &b, sizeof(blufi_frame_t));
            }
        }
    }
    
    // check sequenceNumber
    uint8_t seq = decoder->frame_list[0].sequence_number;
    for (int i=0; i<decoder->frame_list_len; ++i){
        if (seq != decoder->frame_list[i].sequence_number) {
            decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_SEQUENCE_NUMBER_SKIPPED;
            return decoder->state;
        }
        seq++;
    }
    
    // check fragment
    const blufi_frame_t tail = decoder->frame_list[decoder->frame_list_len-1];
    const uint8_t has_fragment = tail.frame_control & BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS;
    if (has_fragment) {
        decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_NEED_MORE_FRAME;
        return decoder->state;
    }
    
    // check contentLength
    int32_t rest_data_len = 0;
    for (int i=0; i<decoder->frame_list_len; ++i) {
        const blufi_frame_t frame = decoder->frame_list[i];
        
        const uint8_t has_fragment = frame.frame_control & BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS;
        if (has_fragment) {
            if (rest_data_len == 0) {
                rest_data_len = frame.total_content_length;
            }
            
            if (rest_data_len != frame.total_content_length) {
                decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_INVALID_CONTENT_LENGTH;
                return decoder->state;
            }
            
            rest_data_len -= frame.data.len;
            if (rest_data_len <= 0) {
                decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_INVALID_CONTENT_LENGTH;
                return decoder->state;
            }
        }
        else {
            if (0 < rest_data_len) {
                rest_data_len -= frame.data.len;
            }
            
            if (rest_data_len != 0) {
                decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_INVALID_CONTENT_LENGTH;
                return decoder->state;
            }
        }
    }
    
    // ok!!
    decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_READY_TO_DECODE;
    return decoder->state;
}

blufi_data_t *blufi_frame_data_decoder_decode(blufi_frame_data_decoder_t *decoder)
{
    assert(decoder != NULL);

    if (decoder->state != BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_READY_TO_DECODE) {
        return NULL;
    }
    
    uint16_t total_content_len = 0;
    for (int i=0; i<decoder->frame_list_len; ++i) {
        total_content_len += decoder->frame_list[i].data.len;
    }
    
    ESP_LOGD(TAG, "total_content_len: %d", total_content_len);
    uint8_t *buf = NULL;
    if (0 < total_content_len) {
        buf = malloc(sizeof(uint8_t) * total_content_len);
        assert(buf != NULL);
    }
    
    uint8_t *pos = buf;
    for (int i=0; i<decoder->frame_list_len; ++i) {
        memcpy(pos, decoder->frame_list[i].data.data, decoder->frame_list[i].data.len);
        pos += decoder->frame_list[i].data.len;
    }
    assert((pos - buf) == total_content_len);
    
    blufi_frame_t head = decoder->frame_list[0];
    
    static const uint8_t MASK = (BLUFI_FRAME_CONTROL_FRAME_IS_ENCRYPTED
                                 | BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM
                                 | BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION
                                 | BLUFI_FRAME_CONTROL_OTHER_PERSON_IS_REQUIRED_TO_REPLY_TO_AN_ACK);

    
    blufi_data_t *data = decode_data(head.type, head.subtype, head.frame_control & MASK, buf, total_content_len);
    free(buf);
    buf = NULL;

    assert(data != NULL);
    for (int i=0; i<decoder->frame_list_len; ++i) {
        free(decoder->frame_list[i].data.data);
    }
    free(decoder->frame_list);
    decoder->frame_list = NULL;
    decoder->frame_list_len = 0;
    decoder->state = BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_EMPTY;

    return data;
}
