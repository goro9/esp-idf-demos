//
//  blufi_types.h
//
//  Created by Kyosuke Kameda on 2020/03/06.
//  Copyright © 2020 Kyosuke Kameda. All rights reserved.
//

#ifndef blufi_types_h
#define blufi_types_h

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    BLUFI_TYPE_CONTROL = 0x00,
    BLUFI_TYPE_DATA = 0x01,
} blufi_type_t;

typedef enum {
    BLUFI_CONTROL_SUBTYPE_ACK = 0x00,
    BLUFI_CONTROL_SUBTYPE_SET_ESP32_TO_THE_SECURITY_MODE = 0x01,
    BLUFI_CONTROL_SUBTYPE_SET_THE_OPMODE_OF_WIFI = 0x02,
    BLUFI_CONTROL_SUBTYPE_CONNECT_ESP32_TO_THE_AP = 0x03,
    BLUFI_CONTROL_SUBTYPE_DISCONNECT_ESP32_FROM_THE_AP = 0x04,
    BLUFI_CONTROL_SUBTYPE_TO_GET_THE_INFORMATION_OF_ESP32S_WIFI_MODE_AND_ITS_STATUS = 0x05,
    BLUFI_CONTROL_SUBTYPE_DISCONNECT_THE_STA_DEVICE_FROM_THE_SOFT_AP = 0x06,
    BLUFI_CONTROL_SUBTYPE_GET_THE_VERSION_INFORMATION = 0x07,
    BLUFI_CONTROL_SUBTYPE_DISCONNECT_THE_BLE_GATT_LINK = 0x08,
    BLUFI_CONTROL_SUBTYPE_GET_THE_WIFI_LIST = 0x09,
} blufi_control_subtype_t;

typedef enum {
    BLUFI_DATA_SUBTYPE_SEND_THE_NEGOTIATION_DATA = 0x00,
    BLUFI_DATA_SUBTYPE_SEND_THE_BSSID_FOR_STA_MODE = 0x01,
    BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_STA_MODE = 0x02,
    BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_STA_MODE = 0x03,
    BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_SOFT_AP_MODE = 0x04,
    BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_SOFT_AP_MODE = 0x05,
    BLUFI_DATA_SUBTYPE_SET_THE_MAXIMUM_CONNECTION_NUMBER_FOR_SOFT_AP_MODE = 0x06,
    BLUFI_DATA_SUBTYPE_SET_THE_AUTHENTICATION_MODE_FOR_THE_SOFT_AP = 0x07,
    BLUFI_DATA_SUBTYPE_SET_THE_CHANNEL_AMOUNT_FOR_SOFT_AP_MODE = 0x08,
    BLUFI_DATA_SUBTYPE_USERNAME = 0x09,
    BLUFI_DATA_SUBTYPE_CA_CERTIFICATION = 0x0A,
    BLUFI_DATA_SUBTYPE_CLIENT_CERTIFICATION = 0x0B,
    BLUFI_DATA_SUBTYPE_SERVER_CERTIFICATION = 0x0C,
    BLUFI_DATA_SUBTYPE_CLIENT_PRIVATE_KEY = 0x0D,
    BLUFI_DATA_SUBTYPE_SERVER_PRIVATE_KEY = 0x0E,
    BLUFI_DATA_SUBTYPE_WIFI_CONNECTIONS_STATE_REPORT = 0x0F,
    BLUFI_DATA_SUBTYPE_VERSION = 0x10,
    BLUFI_DATA_SUBTYPE_WIFI_LIST = 0x11,
    BLUFI_DATA_SUBTYPE_REPORT_ERRPR = 0x12,
    BLUFI_DATA_SUBTYPE_CUSTOM_DATA = 0x13,
} blufi_data_subtype_t;

typedef enum {
    BLUFI_FRAME_CONTROL_FRAME_IS_ENCRYPTED = 1 << 0,
    BLUFI_FRAME_CONTROL_FRAME_CONTAINS_A_CHECK_SUM = 1 << 1,
    BLUFI_FRAME_CONTROL_REPRESENTS_THE_DATA_DIRECTION = 1 << 2,
    BLUFI_FRAME_CONTROL_OTHER_PERSON_IS_REQUIRED_TO_REPLY_TO_AN_ACK = 1 << 3,
    BLUFI_FRAME_CONTROL_THERE_ARE_SUBSEQUENT_DATA_FRAGMENTS = 1 << 4,
} blufi_frame_control_t;

typedef enum {
    BLUFI_DATA_TYPE_ACK = 0,
    BLUFI_DATA_TYPE_SEND_THE_NEGOTIATION_DATA0,
    BLUFI_DATA_TYPE_SEND_THE_NEGOTIATION_DATA1,
    BLUFI_DATA_TYPE_SET_ESP32_TO_THE_SECURITY_MODE,
    BLUFI_DATA_TYPE_SET_THE_OPMODE_OF_WIFI_DATA,
    BLUFI_DATA_TYPE_CUSTOM_DATA,
    BLUFI_DATA_TYPE_GET_THE_WIFI_LIST,
    BLUFI_DATA_TYPE_SEND_THE_SSID_FOR_STA_MODE_DATA,
    BLUFI_DATA_TYPE_SEND_THE_PASSWORD_FOR_STA_MODE_DATA,
    BLUFI_DATA_TYPE_CONNECT_ESP32_TO_THE_AP,
} blufi_data_type_t;

typedef struct {
    uint8_t request_sequence;
} blufi_data_type_ack_payload_t;

typedef struct {
    uint16_t pkg_len;
} blufi_data_type_send_the_negotiation_data0_payload_t;

typedef struct {
    uint16_t prime_len;
    uint8_t *prime;
    uint16_t generator_len;
    uint8_t *generator;
    uint16_t pubkey_len;
    uint8_t *pubkey;
} blufi_data_type_send_the_negotiation_data1_payload_t;

typedef struct {
    bool check_sum_enable;
} blufi_data_type_set_esp32_to_the_security_mode_payload_t;

typedef enum {
   BLUFI_OPMODE_OF_WIFI_NULL = 0,
   BLUFI_OPMODE_OF_WIFI_STA = 1,
   BLUFI_OPMODE_OF_WIFI_SOFT_AP = 1 << 1,
   BLUFI_OPMODE_OF_WIFI_SOFT_AP_AND_STA = BLUFI_OPMODE_OF_WIFI_STA | BLUFI_OPMODE_OF_WIFI_SOFT_AP,
} blufi_opmode_of_wifi_t;

typedef struct {
   blufi_opmode_of_wifi_t opmode_of_wifi;
} blufi_data_type_set_the_opmode_of_wifi_data_payload_t;

typedef struct {
   uint8_t *data;
   uint16_t data_len;
} blufi_data_type_custom_data_payload_t;

typedef struct {
    // NOTHING
} blufi_data_type_get_the_wifi_list_payload_t;

typedef struct {
   char *ssid;
} blufi_data_type_send_the_ssid_for_sta_mode_data_payload_t;

typedef struct {
   char *password;
} blufi_data_type_send_the_password_for_sta_mode_data_payload_t;

typedef struct {
    // NOTHING
} blufi_data_type_connect_esp32_to_the_ap_payload_t;


//
//typedef struct {
//    char *esp32_public_key;
//} blufi_data_type_send_the_negotiation_data_payload_t;
//
//
//typedef struct {
//    char *password;
//} blufi_data_type_send_the_password_for_sta_mode_data_payload_t;
//
//typedef struct {
//    uint8_t subtype;    // 以下の値をとる
//                        // BLUFI_DATA_SUBTYPE_SEND_THE_BSSID_FOR_STA_MODE
//                        // BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_STA_MODE
//                        // BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_STA_MODE
//                        // BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_SOFT_AP_MODE
//                        // BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_SOFT_AP_MODE
//                        // BLUFI_DATA_SUBTYPE_SET_THE_AUTHENTICATION_MODE_FOR_THE_SOFT_AP
//                        // BLUFI_DATA_SUBTYPE_SET_THE_MAXIMUM_CONNECTION_NUMBER_FOR_SOFT_AP_MODE
//                        // BLUFI_DATA_SUBTYPE_SET_THE_CHANNEL_AMOUNT_FOR_SOFT_AP_MODE
//
//    uint8_t length;
//    union {
//        uint8_t bssid[6];    // BLUFI_DATA_SUBTYPE_SEND_THE_BSSID_FOR_STA_MODE
//
//        char *string;        // BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_STA_MODE
//                             // BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_STA_MODE
//                             // BLUFI_DATA_SUBTYPE_SEND_THE_SSID_FOR_SOFT_AP_MODE
//                             // BLUFI_DATA_SUBTYPE_SEND_THE_PASSWORD_FOR_SOFT_AP_MODE
//
//        uint8_t num;         // BLUFI_DATA_SUBTYPE_SET_THE_AUTHENTICATION_MODE_FOR_THE_SOFT_AP
//                             // BLUFI_DATA_SUBTYPE_SET_THE_MAXIMUM_CONNECTION_NUMBER_FOR_SOFT_AP_MODE
//                             // BLUFI_DATA_SUBTYPE_SET_THE_CHANNEL_AMOUNT_FOR_SOFT_AP_MODE
//
//    };
//} blufi_data_type_send_wifi_connection_state_report_data_payload_info_t;
//
//typedef struct {
//    blufi_opmode_of_wifi_t opmode_of_wifi;
//    uint8_t connection_state_of_the_sta;
//    uint8_t connection_state_of_the_soft_ap;
//    size_t info_list_len;
//    blufi_data_type_send_wifi_connection_state_report_data_payload_info_t *info_list;
//} blufi_data_type_send_wifi_connection_state_report_data_payload_t;
//
// typedef struct {
//    uint8_t len;
//    uint8_t rssi;
//    uint8_t *ssid;    // non null terminate
//                      // length = len - 1;
// } blufi_data_type_wifi_list_data_payload_element_t;

// typedef struct {
//    size_t list_len;
//    blufi_data_type_wifi_list_data_payload_element_t *list;
// } blufi_data_type_wifi_list_data_payload_t;

//typedef enum {
//    BLUFI_DATA_TYPE_CUSTOM_DATA_MESSAGE_TYPE_DEVICE_CODE = 0,
//    BLUFI_DATA_TYPE_CUSTOM_DATA_MESSAGE_TYPE_SCAN_SMARTMETER,
//    BLUFI_DATA_TYPE_CUSTOM_DATA_MESSAGE_TYPE_FOTA,
//    BLUFI_DATA_TYPE_CUSTOM_DATA_MESSAGE_TYPE_STATUS,
//} blufi_data_type_custom_data_message_type_t;
//
//typedef struct {
//    size_t id_len;
//    uint8_t *id;
//    blufi_data_type_custom_data_message_type_t type;
//} blufi_data_type_custom_data_message_t;
//
//

typedef struct {
    blufi_data_type_t type;
    uint8_t frame_control;
    union {
        blufi_data_type_ack_payload_t ack;
        blufi_data_type_send_the_negotiation_data0_payload_t send_the_negotiation_data0;
        blufi_data_type_send_the_negotiation_data1_payload_t send_the_negotiation_data1;
        blufi_data_type_set_esp32_to_the_security_mode_payload_t set_esp32_to_the_security_mode;
        blufi_data_type_set_the_opmode_of_wifi_data_payload_t set_the_opmode_of_wifi_data;
        blufi_data_type_custom_data_payload_t custom_data;
        blufi_data_type_get_the_wifi_list_payload_t get_the_wifi_list;
        blufi_data_type_send_the_ssid_for_sta_mode_data_payload_t send_the_ssid_for_sta_mode_data;        blufi_data_type_send_the_password_for_sta_mode_data_payload_t send_the_password_for_sta_mode_data;
        blufi_data_type_connect_esp32_to_the_ap_payload_t connect_esp32_to_the_ap;
//        blufi_data_type_send_wifi_connection_state_report_data_payload_t send_wifi_connection_state_report_data;
//        blufi_data_type_wifi_list_data_payload_t wifi_list_data;
    };
} blufi_data_t;

blufi_data_t* blufi_data_new(blufi_data_type_t type, uint8_t frame_control);
void blufi_data_free(blufi_data_t *data);

#endif /* blufi_types_h */
