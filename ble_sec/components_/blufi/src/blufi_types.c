//
//  blufi_types.c
//
//  Created by Kyosuke Kameda on 2020/03/06.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#include "blufi_types.h"

#include <stdlib.h>
#include <assert.h>

blufi_data_t* blufi_data_new(blufi_data_type_t type, uint8_t frame_control)
{
    blufi_data_t *data = malloc(sizeof(blufi_data_t));
    assert(data != NULL);
    
    data->type = type;
    data->frame_control = frame_control;

    return data;
}

void blufi_data_free(blufi_data_t *data)
{
    if (data == NULL) {
        return;
    }
    
    switch (data->type) {
        case BLUFI_DATA_TYPE_ACK:
            // do nothing
            break;
        case BLUFI_DATA_TYPE_SEND_THE_NEGOTIATION_DATA0:
            // do nothing
            break;
        case BLUFI_DATA_TYPE_SEND_THE_NEGOTIATION_DATA1:
            if (data->send_the_negotiation_data1.prime != NULL) {
                free(data->send_the_negotiation_data1.prime);
            }
            if (data->send_the_negotiation_data1.generator != NULL) {
                free(data->send_the_negotiation_data1.generator);
            }
            if (data->send_the_negotiation_data1.pubkey != NULL) {
                free(data->send_the_negotiation_data1.pubkey);
            }
            break;
        case BLUFI_DATA_TYPE_SET_ESP32_TO_THE_SECURITY_MODE:
            // do nothing
            break;
        case BLUFI_DATA_TYPE_SET_THE_OPMODE_OF_WIFI_DATA:
            // do nothing
            break;
        case BLUFI_DATA_TYPE_CUSTOM_DATA:
            if (data->custom_data.data != NULL) {
                free(data->custom_data.data);
            }
            break;
        case BLUFI_DATA_TYPE_GET_THE_WIFI_LIST:
            // do nothing
            break;
        case BLUFI_DATA_TYPE_SEND_THE_SSID_FOR_STA_MODE_DATA:
            if (data->send_the_ssid_for_sta_mode_data.ssid != NULL) {
                free(data->send_the_ssid_for_sta_mode_data.ssid);
            }
            break;
        case BLUFI_DATA_TYPE_SEND_THE_PASSWORD_FOR_STA_MODE_DATA:
            if (data->send_the_password_for_sta_mode_data.password != NULL) {
                free(data->send_the_password_for_sta_mode_data.password);
            }
            break;
        case BLUFI_DATA_TYPE_CONNECT_ESP32_TO_THE_AP:
            // do nothing
            break;
        default:
            assert(false);
            break;
    }
    
    free(data);
}
