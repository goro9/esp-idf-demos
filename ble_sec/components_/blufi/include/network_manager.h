#pragma once

#include <stdint.h>

#include <host/ble_gatt.h>
#include <host/ble_gap.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_err.h"

typedef int (*nm_cmd_smartmeter_scan_cb)(const char *username, const char *password);
typedef void (*nm_fota_start_cb)();

typedef struct nm_certs_s nm_certs_t;
typedef struct nm_fota_s nm_fota_t;

struct nm_certs_s {
    uint8_t *ptr;
    size_t len;
};

struct nm_fota_s {
    char *host;
    char *path;
    bool ssl;
    char *checksum;
};

typedef enum {
    CMD_DEVICE_CODE_OK = 0,
    CMD_DEVICE_CODE_NO_WIFI,
    CMD_DEVICE_CODE_INVALID_DATA,
    CMD_DEVICE_CODE_QUEUE_IS_FULL,
    CMD_DEVICE_CODE_FAILED_GEN_TOKEN,
    CMD_DEVICE_CODE_TIMEOUT,
    CMD_DEVICE_CODE_NOMEM,
    CMD_DEVICE_CODE_DEVICE_TOKEN_WAS_ALREADY_GOT,
} cmd_device_code_err_t;

// typedef void (*nm_blufi_gap_event_cb)(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

void nm_init();

// esp_ble_adv_data_t *nm_bt_adv_data();

/* network_manager_wifi.c */
// esp_err_t nm_set_ssid_and_password(const char *ssid, const char *password);
// EventBits_t nm_wait_wifi_connected(TickType_t wait);
// bool nm_has_ip();
// bool nm_is_wifi_connected();

/* network_manager_cmd.c */
// void nm_cmd_set_smartmeter_scan_cb(nm_cmd_smartmeter_scan_cb cb);
// int nm_cmd_set_device_code_res(cmd_device_code_err_t err);

/* network_manager_certs.c */
// int nm_certs_update_next(const char *certs);
// int nm_certs_next_verified();
// int nm_certs_use_current();
// int nm_certs_use_next();

/* network_manager_fota.c */
// nm_fota_t *nm_fota_new(uint8_t *host, size_t host_len, uint8_t *path, size_t path_len, bool ssl,
//                        uint8_t *checksum, size_t checksum_len);

// void nm_fota_start(nm_fota_t *fota);
// void nm_fota_add_start_cb(nm_fota_start_cb cb);

/* network_manager_blufi.c */
extern const struct ble_gatt_svc_def NM_GATT_SVR_SVCS[];
void nm_ble_on_sync(void);
void nm_ble_start_advertising(void);
void nm_ble_stop_advertising(void);
