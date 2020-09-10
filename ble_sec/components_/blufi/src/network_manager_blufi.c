#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_bt.h"

#include <host/ble_hs.h>
#include <host/ble_gap.h>
#include <services/gap/ble_svc_gap.h>
#include <os/os_mbuf.h>

#include "network_manager.h"
// #include "network_manager_wifi.h"
#include "network_manager_blufi.h"
// #include "network_manager_cmd.h"
// #include "network_manager_fota.h"
#include "blufi_session.h"
#include "blufi_crypto.h"

#include "ngx-queue.h"
// #include "app_version.h"
// #include "led.h"
// #include "websocket.h"

#define MFG_DATA_SIZE 8
#define MFG_DATA_SERIALNUMBER_SIZE 8
#define SERIALNUMBER_LEN 14

static const char *TAG = "nm-bt";

static const char *HEX_PRIME_FOR_DIFFIE_HELLMANE = "cf5cf5c38419a724957ff5dd323b9c45c3cdd261eb740f69aa94b8bb1a5c96409153bd76b24222d03274e4725a5406092e9e82e9135c643cae98132b0d95f7d65347c68afc1e677da90e51bbab5f5cf429c291b4ba39c6b2dc5e8c7231e46aa7728e87664532cdf547be20c9a3fa8342be6e34371a27c06f7dc0edddd2f86373";
static const char *GENERATOR_FOR_DIFFIE_HELLMAN = "2";

static uint8_t s_own_addr_type;

static int bleprph_advertise(void);
static int send_status(void);

typedef struct {
    blufi_session_t *session;
    uint16_t conn_handle;
    uint16_t read_notify_attr_handler;
    uint16_t app_mtu;
    uint8_t *buf;
    blufi_data_t *negotiation0;
    blufi_data_t *negotiation1;
    blufi_data_t *set_esp32_to_the_security_mode;
    blufi_data_t *set_the_opmode_of_wifi;
    blufi_data_t *send_the_ssid_for_sta_mode_data;
    blufi_data_t *send_the_password_for_sta_mode_data;
} blufi_context_t;

typedef union {
    char letter;
    struct {
        uint8_t lower:4;
        uint8_t upper:4;
    } bin;
    uint8_t number;
} serialnumber_data_t;

// 定義済みの UUID フォーマット `0000XXXX-0000-1000-8000-00805f9b34fb` なので BLE_UUID16_INIT でよい
// https://www.bluetooth.com/specifications/gatt/services/
// ただし、それでいいのかって問題があるが一旦既存と同じにする
// 0000ffff-0000-1000-8000-00805f9b34fb
static const ble_uuid16_t SERVICE_UUID = BLE_UUID16_INIT(0xFFFF);

// 0000ff01-0000-1000-8000-00805f9b34fb
static const ble_uuid16_t WRITE_UUID = BLE_UUID16_INIT(0xFF01);

// 0000ff02-0000-1000-8000-00805f9b34fb
static const ble_uuid16_t READ_NOTIFY_UUID = BLE_UUID16_INIT(0xFF02);

static blufi_context_t BLUFI_CONTEXT = {
    .session = NULL,
    .conn_handle = 0,
    .read_notify_attr_handler = 0,
    .app_mtu = 0,
    .buf = NULL,
    .negotiation0 = NULL,
    .negotiation1 = NULL,
    .set_esp32_to_the_security_mode = NULL,
    .set_the_opmode_of_wifi = NULL,
    .send_the_ssid_for_sta_mode_data = NULL,
    .send_the_password_for_sta_mode_data = NULL,
};

/*
 * bleprph_gap_event, access_cb, nm_blufi_send_wifi_list, nm_blufi_send_status でのみ排他処理を行う
 * 他の関数ではすでに排他処理されているものとして BLUFI_CONTEXT にアクセスする。
 */
static xSemaphoreHandle s_BLUFI_CONTEXT_mu = NULL;

static int notifiy_writer(blufi_session_t *session, uint16_t conn_handle, uint16_t attr_handle, const blufi_frame_t *frame_list, size_t frame_list_len)
{
    ESP_LOGD(TAG, "%s:%d", __FUNCTION__, __LINE__);

    assert(session != NULL);
    assert(frame_list != NULL);

    for (int i=0; i<frame_list_len; ++i) {
        uint8_t *buf = NULL;
        ssize_t len = blufi_frame_encode(&buf, &frame_list[i]);
        assert(buf != NULL);
        assert(0 < len);
        struct os_mbuf *om = ble_hs_mbuf_from_flat(buf, len);
        int r = ble_gattc_notify_custom(conn_handle, attr_handle, om);    // 内部で om は開放される
        free(buf);
        if (r != 0) {
            ESP_LOGW(TAG, "ble_gattc_notify_custom fail:%d", r);
            return r;
        }
        session->esp32_sequence_number++;
    }
    return 0;
}

static int bleprph_gap_event(struct ble_gap_event *event, void *arg)
{
    ESP_LOGD(TAG, "%s:%d", __FUNCTION__, __LINE__);
    ESP_LOGD(TAG, "event->type: %d", event->type);

    switch (event->type){
        case BLE_GAP_EVENT_CONNECT:
        {
            ESP_LOGI(TAG, "blufi session connect");

            if (event->connect.status != 0) {
                /* Connection failed; resume advertising. */
                int r = bleprph_advertise();
                if (r) {
                    ESP_LOGE(TAG, "bleprph_advertise fail: %d", r);
                    if (r != BLE_HS_EALREADY) {
                        assert(false);
                    }
                }
                break;
            }

            remo_set_state(REMO_STATE_BT_CONNECTED, true);

            ESP_LOGD(TAG, "xSemaphoreTake %s:%d", __FUNCTION__, __LINE__);
            xSemaphoreTake(s_BLUFI_CONTEXT_mu, portMAX_DELAY);
            blufi_context_t *blufi_ctx = (blufi_context_t*)arg;

            assert(blufi_ctx->session == NULL);    // TODO: 複数接続は認めない!!
            blufi_ctx->session = blufi_session_new(notifiy_writer);
            blufi_ctx->session->mtu = 125;    // bludroid の mtu は 125 になっているようなので、それに合わせる
            blufi_ctx->app_mtu = 0;
            blufi_ctx->buf = NULL;
            blufi_ctx->negotiation0 = NULL;
            blufi_ctx->negotiation1 = NULL;
            blufi_ctx->set_esp32_to_the_security_mode = NULL;
            blufi_ctx->set_the_opmode_of_wifi = NULL;
            blufi_ctx->send_the_ssid_for_sta_mode_data = NULL;
            blufi_ctx->send_the_password_for_sta_mode_data = NULL;

            xSemaphoreGive(s_BLUFI_CONTEXT_mu);
            ESP_LOGD(TAG, "xSemaphoreGive %s:%d", __FUNCTION__, __LINE__);

            goto cleanup;
        }
        case BLE_GAP_EVENT_DISCONNECT:
        {
            ESP_LOGI(TAG, "blufi session disconnect");

            nm_fota_notify_disconnected();
            remo_set_state(REMO_STATE_BT_CONNECTED | REMO_STATE_BT_CONNECTED_FOR_SETUP, false);

            ESP_LOGD(TAG, "xSemaphoreTake %s:%d", __FUNCTION__, __LINE__);
            xSemaphoreTake(s_BLUFI_CONTEXT_mu, portMAX_DELAY);
            blufi_context_t *blufi_ctx = (blufi_context_t*)arg;

            assert(blufi_ctx->session != NULL);
            blufi_session_free(blufi_ctx->session);
            blufi_ctx->session = NULL;
            blufi_ctx->app_mtu = 0;
            if (blufi_ctx->buf != NULL) {
                free(blufi_ctx->buf);
            }
            blufi_ctx->buf = NULL;

            if (blufi_ctx->negotiation0 != NULL) {
                blufi_data_free(blufi_ctx->negotiation0);
            }
            blufi_ctx->negotiation0 = NULL;

            if (blufi_ctx->negotiation1 != NULL) {
                blufi_data_free(blufi_ctx->negotiation1);
            }
            blufi_ctx->negotiation1 = NULL;

            if (blufi_ctx->set_esp32_to_the_security_mode != NULL) {
                blufi_data_free(blufi_ctx->set_esp32_to_the_security_mode);
            }
            blufi_ctx->set_esp32_to_the_security_mode = NULL;

            if (blufi_ctx->set_the_opmode_of_wifi != NULL) {
                blufi_data_free(blufi_ctx->set_the_opmode_of_wifi);
            }
            blufi_ctx->set_the_opmode_of_wifi = NULL;

            if (blufi_ctx->send_the_ssid_for_sta_mode_data != NULL) {
                blufi_data_free(blufi_ctx->send_the_ssid_for_sta_mode_data);
            }
            blufi_ctx->send_the_ssid_for_sta_mode_data = NULL;

            if (blufi_ctx->send_the_password_for_sta_mode_data != NULL) {
                blufi_data_free(blufi_ctx->send_the_password_for_sta_mode_data);
            }
            blufi_ctx->send_the_password_for_sta_mode_data = NULL;

            xSemaphoreGive(s_BLUFI_CONTEXT_mu);
            ESP_LOGD(TAG, "xSemaphoreGive %s:%d", __FUNCTION__, __LINE__);

            /* Connection terminated; resume advertising. */
            int r = bleprph_advertise();
            if (r) {
                ESP_LOGE(TAG, "bleprph_advertise fail: %d", r);
                if (r != BLE_HS_EALREADY) {
                    assert(false);
                }
            }
            goto cleanup;
        }
        case BLE_GAP_EVENT_CONN_UPDATE:
        case BLE_GAP_EVENT_CONN_UPDATE_REQ:
        case BLE_GAP_EVENT_L2CAP_UPDATE_REQ:
        case BLE_GAP_EVENT_TERM_FAILURE:
        case BLE_GAP_EVENT_DISC:
        case BLE_GAP_EVENT_DISC_COMPLETE:
        case BLE_GAP_EVENT_ADV_COMPLETE:
        case BLE_GAP_EVENT_ENC_CHANGE:
        case BLE_GAP_EVENT_PASSKEY_ACTION:
        case BLE_GAP_EVENT_NOTIFY_RX:
        case BLE_GAP_EVENT_NOTIFY_TX:
            // 一旦無視する
            break;
        case BLE_GAP_EVENT_SUBSCRIBE:
        {
            ESP_LOGD(TAG, "subscribe event; conn_handle=%d attr_handle=%d "
                          "reason=%d prevn=%d curn=%d previ=%d curi=%d\n",
                    event->subscribe.conn_handle,
                    event->subscribe.attr_handle,
                    event->subscribe.reason,
                    event->subscribe.prev_notify,
                    event->subscribe.cur_notify,
                    event->subscribe.prev_indicate,
                    event->subscribe.cur_indicate);

            ESP_LOGD(TAG, "xSemaphoreTake %s:%d", __FUNCTION__, __LINE__);
            xSemaphoreTake(s_BLUFI_CONTEXT_mu, portMAX_DELAY);
            blufi_context_t *blufi_ctx = (blufi_context_t*)arg;

            blufi_ctx->read_notify_attr_handler = event->subscribe.attr_handle;

            xSemaphoreGive(s_BLUFI_CONTEXT_mu);
            ESP_LOGD(TAG, "xSemaphoreGive %s:%d", __FUNCTION__, __LINE__);
            goto cleanup;
        }
        case BLE_GAP_EVENT_MTU:
        {
            ESP_LOGD(TAG, "mtu update event; conn_handle=%d cid=%d mtu=%d",
                     event->mtu.conn_handle,
                     event->mtu.channel_id,
                     event->mtu.value);

            ESP_LOGD(TAG, "xSemaphoreTake %s:%d", __FUNCTION__, __LINE__);
            xSemaphoreTake(s_BLUFI_CONTEXT_mu, portMAX_DELAY);
            blufi_context_t *blufi_ctx = (blufi_context_t*)arg;

            // 途中で複数回 mtu 変えるのは禁止！！
            assert(blufi_ctx->app_mtu == 0);
            assert(blufi_ctx->buf == NULL);

            blufi_ctx->app_mtu = event->mtu.value;

            // ここで確保したメモリは切断されるまで、再利用される。
            blufi_ctx->buf = malloc(sizeof(uint8_t) * blufi_ctx->app_mtu);
            assert(blufi_ctx->buf != NULL);

            xSemaphoreGive(s_BLUFI_CONTEXT_mu);
            ESP_LOGD(TAG, "xSemaphoreGive %s:%d", __FUNCTION__, __LINE__);
            goto cleanup;
        }        
        case BLE_GAP_EVENT_IDENTITY_RESOLVED:
        case BLE_GAP_EVENT_REPEAT_PAIRING:
        case BLE_GAP_EVENT_PHY_UPDATE_COMPLETE:
        case BLE_GAP_EVENT_EXT_DISC:
            // 一旦無視する
            goto cleanup;
        default:
            assert(false);
            break;
    }

cleanup:
    return 0;
}

static int handle_ack(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    blufi_data_free(data);
    return 0;
}

static int handle_send_the_negotiation_data0(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    assert(blufi_ctx->negotiation0 == NULL);
    blufi_ctx->negotiation0 = data;
    return 0;
}

static int handle_send_the_negotiation_data1(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    assert(blufi_ctx->negotiation1 == NULL);
    blufi_ctx->negotiation1 = data;

    blufi_crypto_create_diffie_hellman_key_pair(HEX_PRIME_FOR_DIFFIE_HELLMANE,
                                                GENERATOR_FOR_DIFFIE_HELLMAN,
                                                blufi_ctx->session->private_key,
                                                blufi_ctx->session->public_key);

    ESP_LOGD(TAG, "blufi_ctx->negotiation1->send_the_negotiation_data1.pubkey_len: %d", blufi_ctx->negotiation1->send_the_negotiation_data1.pubkey_len);
    blufi_crypto_generate_secret_key(
        HEX_PRIME_FOR_DIFFIE_HELLMANE,
        blufi_ctx->session->private_key,
        blufi_ctx->negotiation1->send_the_negotiation_data1.pubkey,
        blufi_ctx->session->secret_key);

    int r = blufi_session_post_send_the_negotiation_data(blufi_ctx->session,
                                                         conn_handle,
                                                         blufi_ctx->read_notify_attr_handler,
                                                         blufi_ctx->session->public_key,
                                                         sizeof(blufi_ctx->session->public_key)/sizeof(blufi_ctx->session->public_key[0]));
    if (r != 0) {
        ESP_LOGW(TAG, "blufi_session_post_send_the_negotiation_data fail: %d", r);
    }

    return r;
}

static int handle_set_esp32_to_the_security_mode(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    blufi_ctx->set_esp32_to_the_security_mode = data;
    return 0;
}

static int handle_set_the_opmode_of_wifi_data(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    blufi_ctx->set_the_opmode_of_wifi = data;
    
    uint8_t fc = data->frame_control & BLUFI_FRAME_CONTROL_OTHER_PERSON_IS_REQUIRED_TO_REPLY_TO_AN_ACK;
    assert(0 < fc);

    int r = blufi_session_post_ack(
        blufi_ctx->session,
        conn_handle,
        blufi_ctx->read_notify_attr_handler);
    if (r != 0) {
        ESP_LOGW(TAG, "blufi_session_post_ack fail: %d", r);
    }
    return r;
}

static int execute_cmd_cb(nm_execute_cmd_cb_type_t type, uint8_t *buf, size_t buf_len, void *arg)
{
    blufi_context_t *blufi_ctx = (blufi_context_t *)arg;

    int r = 0;
    switch (type) {
        case NM_EXECUTE_CMD_CB_TYPE_STATUS:
        case NM_EXECUTE_CMD_CB_TYPE_DEVICE_CODE:
        case NM_EXECUTE_CMD_CB_TYPE_VERSION:
            r = blufi_session_post_custom_data(
                blufi_ctx->session,
                blufi_ctx->conn_handle,
                blufi_ctx->read_notify_attr_handler,
                buf,
                buf_len);
            if (r != 0) {
                ESP_LOGW(TAG, "blufi_session_post_custom_data fail: %d", r);
            }
            break;
        default:
            assert(false);
            break;
    }
    return r;
}

static int handle_custom_data(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    int r = nm_execute_cmd(data->custom_data.data, data->custom_data.data_len, execute_cmd_cb, blufi_ctx);
    blufi_data_free(data);
    return r;
}

static int handle_get_the_wifi_list(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    blufi_ctx->conn_handle = conn_handle;
    esp_err_t err = nm_wifi_start_scan();
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "wifi scan failed: %d", err);
        blufi_data_free(data);
        return -1;
    }
    remo_set_state(REMO_STATE_BT_CONNECTED_FOR_SETUP, true);
    blufi_data_free(data);
    return 0;
}

static int handle_send_the_ssid_for_sta_mode_data(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    bool b;
    ESP_ERROR_CHECK(websocket_has_device_token(&b));
    if (b) {
        ESP_LOGI(TAG, "device_token was already got. so can not update ssid");
        return 0;    // handle_connect_esp32_to_the_ap のタイミングでエラーを返す
    }

    blufi_ctx->send_the_ssid_for_sta_mode_data = data;
    return 0;
}

static int handle_send_the_password_for_sta_mode_data(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    bool b;
    ESP_ERROR_CHECK(websocket_has_device_token(&b));
    if (b) {
        ESP_LOGI(TAG, "device_token was already got. so can not update password");
        return 0;    // handle_connect_esp32_to_the_ap のタイミングでエラーを返す
    }

    blufi_ctx->send_the_password_for_sta_mode_data = data;
    return 0;
}

static int handle_connect_esp32_to_the_ap(blufi_context_t *blufi_ctx, uint16_t conn_handle, blufi_data_t *data)
{
    ESP_LOGI(TAG, "blufi request wifi connect to AP");

    bool b;
    ESP_ERROR_CHECK(websocket_has_device_token(&b));
    if (b) {
        ESP_LOGI(TAG, "device_token was already got. so can not connect to AP");
        send_status();
        return 0;    // send_status で返しているのでここでは何もしない
    }

    char *ssid = blufi_ctx->send_the_ssid_for_sta_mode_data->send_the_ssid_for_sta_mode_data.ssid;
    char *password = blufi_ctx->send_the_password_for_sta_mode_data->send_the_password_for_sta_mode_data.password;

    nm_wifi_set_ssid((uint8_t*)ssid, strlen(ssid));
    nm_wifi_set_pass((uint8_t*)password, strlen(password));
    nm_wifi_reconnect();
    remo_set_state(REMO_STATE_NO_WIFI_INFO | REMO_STATE_BT_CONNECTED_FOR_SETUP, false);

    blufi_data_free(data);
    return 0;
}


static int access_cb(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg)
{
    ESP_LOGD(TAG, "%s:%d", __FUNCTION__, __LINE__);
    ESP_LOGD(TAG, "ctxt->op: %d", ctxt->op);
    ESP_LOGD(TAG, "conn_handle: %d", conn_handle);
    ESP_LOGD(TAG, "attr_handle: %d", attr_handle);
    ESP_LOGD(TAG, "ble_uuid_cmp(uuid, &WRITE_UUID.u): %d", ble_uuid_cmp(ctxt->chr->uuid, &WRITE_UUID.u));
    ESP_LOGD(TAG, "ble_uuid_cmp(uuid, &READ_NOTIFY_UUID.u): %d", ble_uuid_cmp(ctxt->chr->uuid, &READ_NOTIFY_UUID.u));

    const ble_uuid_t *uuid;

    ESP_LOGD(TAG, "xSemaphoreTake %s:%d", __FUNCTION__, __LINE__);
    xSemaphoreTake(s_BLUFI_CONTEXT_mu, portMAX_DELAY);

    blufi_context_t *blufi_ctx = (blufi_context_t*)arg;
    uuid = ctxt->chr->uuid;

    int res = 0;

    if (ble_uuid_cmp(uuid, &WRITE_UUID.u) == 0) {
        assert(blufi_ctx->app_mtu != 0);

        uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
        if (blufi_ctx->app_mtu < om_len) {
            res = BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            goto cleanup;
        }

        uint16_t read_len = 0;
        int rc = ble_hs_mbuf_to_flat(ctxt->om, blufi_ctx->buf, blufi_ctx->app_mtu, &read_len);
        if (rc != 0) {
            res = BLE_ATT_ERR_UNLIKELY;
            goto cleanup;
        }
        ESP_LOGD(TAG, "ble_hs_mbuf_to_flat. read_len: %d", read_len);

        int r = blufi_session_update(blufi_ctx->session, blufi_ctx->buf, read_len);

        ESP_LOGD(TAG, "blufi_session_update: %d", r);
        if (r < 0) {
            res = BLE_ATT_ERR_UNLIKELY;
            goto cleanup;
        }

        switch((blufi_frame_data_decoder_update_result_t)r) {
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_EMPTY:                      // fall through
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_TYPE_MISMATCH:              // fall through
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_SUBTYPE_MISMATCH:           // fall through
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_DATA_DIRECTION_MISMATCH:    // fall through
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_CHECKSUM_MISMATCH:          // fall through
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_SEQUENCE_NUMBER_SKIPPED:    // fall through
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_INVALID_CONTENT_LENGTH:
                res = BLE_ATT_ERR_UNLIKELY;
                goto cleanup;
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_NEED_MORE_FRAME:
                ESP_LOGD(TAG, "NEED MORE FRAME!!");
                goto cleanup;
            case BLUFI_FRAME_DATA_DECODER_UPDATE_RESULT_READY_TO_DECODE:
                ESP_LOGD(TAG, "READY TO DECODE");
                blufi_data_t *data = blufi_session_decode(blufi_ctx->session);
                assert(data != NULL);
                ESP_LOGD(TAG, "data->type: %d", data->type);

#define CHECK_NEGOTIATED()                            \
if (!blufi_ctx->session->negotiated){                 \
    ESP_LOGE(TAG, "need security negotiation first"); \
    res = BLE_ATT_ERR_UNLIKELY;                       \
    goto cleanup;                                     \
}

                switch (data->type) {
                    case BLUFI_DATA_TYPE_ACK:
                        r = handle_ack(blufi_ctx, conn_handle, data);
                        break;
                    case BLUFI_DATA_TYPE_SEND_THE_NEGOTIATION_DATA0:
                        r = handle_send_the_negotiation_data0(blufi_ctx, conn_handle, data);
                        break;
                    case BLUFI_DATA_TYPE_SEND_THE_NEGOTIATION_DATA1:
                        r = handle_send_the_negotiation_data1(blufi_ctx, conn_handle, data);
                        break;
                    case BLUFI_DATA_TYPE_SET_ESP32_TO_THE_SECURITY_MODE:
                    {
                        CHECK_NEGOTIATED()
                        r = handle_set_esp32_to_the_security_mode(blufi_ctx, conn_handle, data);
                        assert(blufi_ctx->set_esp32_to_the_security_mode->set_esp32_to_the_security_mode.check_sum_enable == true);
                        break;
                    }
                    case BLUFI_DATA_TYPE_SET_THE_OPMODE_OF_WIFI_DATA:
                    {
                        CHECK_NEGOTIATED()
                        r = handle_set_the_opmode_of_wifi_data(blufi_ctx, conn_handle, data);
                        assert(blufi_ctx->set_the_opmode_of_wifi->set_the_opmode_of_wifi_data.opmode_of_wifi == BLUFI_OPMODE_OF_WIFI_STA);
                    }
                        break;
                    case BLUFI_DATA_TYPE_CUSTOM_DATA:
                    {
                        CHECK_NEGOTIATED()
                        r = handle_custom_data(blufi_ctx, conn_handle, data);
                        break;
                    }
                    case BLUFI_DATA_TYPE_GET_THE_WIFI_LIST:
                    {
                        CHECK_NEGOTIATED()
                        r = handle_get_the_wifi_list(blufi_ctx, conn_handle, data);
                        break;
                    }
                    case BLUFI_DATA_TYPE_SEND_THE_SSID_FOR_STA_MODE_DATA:
                    {
                        CHECK_NEGOTIATED()
                        r = handle_send_the_ssid_for_sta_mode_data(blufi_ctx, conn_handle, data);
                        break;
                    }
                    case BLUFI_DATA_TYPE_SEND_THE_PASSWORD_FOR_STA_MODE_DATA:
                    {
                        CHECK_NEGOTIATED()
                        r = handle_send_the_password_for_sta_mode_data(blufi_ctx, conn_handle, data);
                        break;
                    }
                    case BLUFI_DATA_TYPE_CONNECT_ESP32_TO_THE_AP:
                    {
                        CHECK_NEGOTIATED()
                        r = handle_connect_esp32_to_the_ap(blufi_ctx, conn_handle, data);
                        break;
                    }
                    default:
                        assert(false);
                }
                if (r != 0) {
                    res = BLE_ATT_ERR_UNLIKELY;
                }
                goto cleanup;
#undef CHECK_NEGOTIATED
            default:
                assert(false);
        }
    }

    if (ble_uuid_cmp(uuid, &READ_NOTIFY_UUID.u) == 0) {
        switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_READ_CHR: {
            static const uint8_t val = 0x00;
            int rc = os_mbuf_append(ctxt->om, &val, sizeof(val));
            res = rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
            goto cleanup;
        }
        default:
            assert(false);
        }
    }

cleanup:
    xSemaphoreGive(s_BLUFI_CONTEXT_mu);
    ESP_LOGD(TAG, "xSemaphoreGive %s:%d", __FUNCTION__, __LINE__);
    return res;
}

// defind in network_manager.h
const struct ble_gatt_svc_def NM_GATT_SVR_SVCS[] = {
    {
        /*** Service: Security test. */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &SERVICE_UUID.u,
        .characteristics = (struct ble_gatt_chr_def[])
        { 
            {
                .uuid = &WRITE_UUID.u,
                .access_cb = access_cb,                
                .flags = BLE_GATT_CHR_F_WRITE,
                .arg = &BLUFI_CONTEXT,
            }, {
                .uuid = &READ_NOTIFY_UUID.u,
                .access_cb = access_cb,                
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
                .arg = &BLUFI_CONTEXT,
                .val_handle = &BLUFI_CONTEXT.read_notify_attr_handler,
            }, {
                0, /* No more characteristics in this service. */
            }
        },
    },

    {
        0, /* No more services. */
    },
};

void nm_ble_on_sync(void)
{
    int rc;

    /* Figure out address to use while advertising (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "error determining address type; rc=%d", rc);
        assert(false);
        return;
    }

    /* Printing ADDR */
    uint8_t addr_val[6] = {0};
    rc = ble_hs_id_copy_addr(s_own_addr_type, addr_val, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "error determining address type; rc=%d", rc);
        assert(false);
        return;
    }

    ESP_LOGI(TAG, "BLE mac address: %02X:%02X:%02X:%02X:%02X:%02X",
    addr_val[0], addr_val[1], addr_val[2], addr_val[3], addr_val[4], addr_val[5]);

    rc = bleprph_advertise();
    if (rc) {
        ESP_LOGE(TAG, "bleprph_advertise fail: %d", rc);
        if (rc != BLE_HS_EALREADY) {
            assert(false);
        }
    }
}

/**
 * シリアルナンバーの文字列->送信用バイナリ変換
 *
 * @param bin               送信用バイナリ形式のシリアルナンバー
 *                          ex) 01 37 31 91 20 00 00 16 (binary size: 8)
 * @param str               文字列形式のシリアルナンバー
 *                          ex) 1W319120000016          (string size:15 length:14)
 *
 */
static void serialnumber_str_to_bin(uint8_t *bin, const char *str) {
    assert(str != NULL);

    serialnumber_data_t *buf = (serialnumber_data_t *)bin;

    char str_buf[2] = {str[0], '\0'};
    buf[0].bin.lower = strtol(str_buf, NULL, 10);
    buf[1].letter = str[1];
    int i = 2;
    while (i < MFG_DATA_SERIALNUMBER_SIZE) {
        int str_i = (i * 2) - 2;
        str_buf[0] = str[str_i];
        buf[i].bin.upper = strtol(str_buf, NULL, 10);
        str_buf[0] = str[str_i + 1];
        buf[i].bin.lower = strtol(str_buf, NULL, 10);
        ++i;
    }
}

static void set_mfg_data(struct ble_hs_adv_fields *fields) {
    uint8_t *mfg_data = calloc(MFG_DATA_SIZE, sizeof(uint8_t));
    assert(mfg_data != NULL);

    const char *sn_str = app_serialnumber();
    serialnumber_str_to_bin(mfg_data, sn_str);
    fields->mfg_data = mfg_data;
    fields->mfg_data_len = MFG_DATA_SIZE;
}

static void free_mfg_data(struct ble_hs_adv_fields *fields) {
    if (fields->mfg_data != NULL) {
        free(fields->mfg_data);
        fields->mfg_data = NULL;
    }
}

/**
 * Enables advertising with the following parameters:
 *     o General discoverable mode.
 *     o Undirected connectable mode.
 */
static int bleprph_advertise(void)
{
    struct ble_gap_adv_params adv_params;
    struct ble_hs_adv_fields fields;
    const char *name;
    int rc;

    /**
     *  Set the advertisement data included in our advertisements:
     *     o Flags (indicates advertisement type and other general info).
     *     o Advertising tx power.
     *     o Device name.
     *     o 16-bit service UUIDs (alert notifications).
     */

    memset(&fields, 0, sizeof(fields));

    /* Advertise two flags:
     *     o Discoverability in forthcoming advertisement (general)
     *     o BLE-only (BR/EDR unsupported).
     */
    fields.flags = BLE_HS_ADV_F_DISC_GEN |
                   BLE_HS_ADV_F_BREDR_UNSUP;

    /* Indicate that the TX power level field should be included; have the
     * stack fill this value automatically.  This is done by assigning the
     * special value BLE_HS_ADV_TX_PWR_LVL_AUTO.
     */
    fields.tx_pwr_lvl_is_present = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;

    /**
     * Set the data included in our scan response:
     *    o Manufacture Specific.
     *      o Serial Number.
     */

    name = ble_svc_gap_device_name();
    fields.name = (uint8_t *)name;
    fields.name_len = strlen(name);
    fields.name_is_complete = 1;

    fields.uuids16 = (ble_uuid16_t[]) { BLE_UUID16_INIT(0xFFFF) };
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "error setting advertisement data; rc=%d", rc);
        assert(false);
        return rc;
    }

    struct ble_hs_adv_fields rsp_fields;
    memset(&rsp_fields, 0, sizeof(rsp_fields));
    set_mfg_data(&rsp_fields);

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "error setting scan response data; rc=%d", rc);
        assert(false);
        return rc;
    }

    free_mfg_data(&rsp_fields);

    /* Begin advertising. */
    memset(&adv_params, 0, sizeof adv_params);
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                           &adv_params, bleprph_gap_event, &BLUFI_CONTEXT);
    if (rc != 0) {
        ESP_LOGE(TAG, "error enabling advertisement; rc=%d", rc);
        return rc;
    }
    return 0;
}

static int send_status()
{
    if (BLUFI_CONTEXT.session == NULL) {
        ESP_LOGI(TAG, "blufi session already closed");
        return -1;
    }

    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);

    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pk, 2); /* cmd, result */

    nm_cmd_pack_status(&pk);

    ESP_LOGD(TAG, "push status:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, sbuf.data, sbuf.size, ESP_LOG_DEBUG);

    int r = blufi_session_post_custom_data(
            BLUFI_CONTEXT.session,
            BLUFI_CONTEXT.conn_handle,
            BLUFI_CONTEXT.read_notify_attr_handler,
            (uint8_t*)sbuf.data,
            sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);
    if (r != 0) {
        ESP_LOGE(TAG, "blufi_session_post_custom_data fail: %d", r);
    }
    return r;
}

void nm_blufi_init()
{
    s_BLUFI_CONTEXT_mu = xSemaphoreCreateMutex();
    nm_cmd_init();
}

int nm_blufi_send_wifi_list(uint16_t count, wifi_ap_record_t *aps)
{
    int r = 0;

    ESP_LOGD(TAG, "xSemaphoreTake %s:%d", __FUNCTION__, __LINE__);
    xSemaphoreTake(s_BLUFI_CONTEXT_mu, portMAX_DELAY);
    if (BLUFI_CONTEXT.session == NULL) {
        ESP_LOGI(TAG, "blufi session already closed");
        r = -1;
        goto cleanup;
    }

    r = blufi_session_post_wifi_list(
        BLUFI_CONTEXT.session,
        BLUFI_CONTEXT.conn_handle,
        BLUFI_CONTEXT.read_notify_attr_handler,
        aps,
        count);
    if (r != 0) {
        ESP_LOGE(TAG, "blufi_session_post_wifi_list fail: %d", r);
        goto cleanup;
    }
    
cleanup:
    xSemaphoreGive(s_BLUFI_CONTEXT_mu);
    ESP_LOGD(TAG, "xSemaphoreGive %s:%d", __FUNCTION__, __LINE__);
    return r;
}

int nm_blufi_send_status()
{
    int r = 0;
    ESP_LOGD(TAG, "xSemaphoreTake %s:%d", __FUNCTION__, __LINE__);
    xSemaphoreTake(s_BLUFI_CONTEXT_mu, portMAX_DELAY);
    r = send_status();
    xSemaphoreGive(s_BLUFI_CONTEXT_mu);
    ESP_LOGD(TAG, "xSemaphoreGive %s:%d", __FUNCTION__, __LINE__);
    return r;
}

void nm_ble_start_advertising(void) {
    if (!ble_gap_adv_active()) {
        int r = bleprph_advertise();
        if (r){
            ESP_LOGE(TAG, "bleprph_advertise fail: %d", r);
            if (r != BLE_HS_EALREADY) {
                assert(false);
            }
        }
    }
}

void nm_ble_stop_advertising(void) {
    if (ble_gap_adv_active()) {
        int r = ble_gap_adv_stop();
        if (r) {
            ESP_LOGE(TAG, "ble_gap_adv_stop fail: %d", r);
            assert(false);
        }
    }
}
