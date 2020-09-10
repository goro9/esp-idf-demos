#pragma once

#include "esp_wifi.h"

void nm_blufi_init();

int nm_blufi_send_wifi_list(uint16_t count, wifi_ap_record_t *aps);
int nm_blufi_send_status();
