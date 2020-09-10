#include <assert.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "tcpip_adapter.h"
#include "mdns.h"

#include "network_manager.h"
// #include "network_manager_wifi.h"
#include "network_manager_blufi.h"
// #include "network_manager_fota.h"
// #include "led.h"
// #include "app_version.h"

static const char *TAG = "nm";

void nm_init()
{
    // led_init();

    // nm_wifi_init();
    // app_version_init();

    // ESP_ERROR_CHECK(mdns_init());
    // ESP_ERROR_CHECK(mdns_hostname_set(app_hostname()));
    // ESP_ERROR_CHECK(mdns_service_add(NULL, "_remo", "_tcp", 80, NULL, 0));

    nm_blufi_init();
    // nm_fota_init();
}
