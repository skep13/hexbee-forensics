/* HexBee Scout — ESP32-S3 field agent firmware.
 *
 * Responsibilities (matching the platform contract with the Hive):
 *   - join field Wi-Fi, connect to the Hive's MQTT broker
 *   - publish JSON events to hexbee/events/<device> (QoS 1)
 *   - buffer events locally while offline, flush in order on reconnect
 *   - heartbeat every CONFIG_HEXBEE_HEARTBEAT_SECONDS
 *   - report USB activity via usb_watch (simulation mode until the
 *     TinyUSB acquisition path is hardware-validated)
 *
 * Event JSON shape (must match hexbee_hive.normalize):
 *   {"device":"Scout01","event_type":"usb_inserted",
 *    "occurred_at":<unix epoch>,"payload":{...}}
 * The Hive accepts epoch numbers for occurred_at, which saves the Scout
 * from needing an RTC before SNTP sync completes.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mqtt_client.h"
#include "nvs_flash.h"

#include "event_buffer.h"
#include "usb_watch.h"

static const char *TAG = "hexbee_scout";

static esp_mqtt_client_handle_t s_mqtt;
static volatile bool s_mqtt_connected;
static char s_topic[64];

/* ---------------------------------------------------------------- events */

static void emit_event(const char *event_type, const char *payload_json)
{
    char json[EVENT_MAX_LEN];
    int n = snprintf(json, sizeof(json),
                     "{\"device\":\"%s\",\"event_type\":\"%s\","
                     "\"occurred_at\":%lld,\"payload\":%s}",
                     CONFIG_HEXBEE_DEVICE_NAME, event_type,
                     (long long)time(NULL),
                     payload_json && payload_json[0] ? payload_json : "{}");
    if (n < 0 || n >= (int)sizeof(json)) {
        ESP_LOGE(TAG, "event too large, dropped: %s", event_type);
        return;
    }

    if (s_mqtt_connected &&
        esp_mqtt_client_publish(s_mqtt, s_topic, json, 0, 1, 0) >= 0) {
        return;
    }
    /* Offline (or publish failed): buffer for later. */
    event_buffer_push(json);
    ESP_LOGI(TAG, "buffered %s (%u queued)", event_type,
             (unsigned)event_buffer_count());
}

static void flush_buffered(void)
{
    char json[EVENT_MAX_LEN];
    while (s_mqtt_connected && event_buffer_peek(json, sizeof(json))) {
        if (esp_mqtt_client_publish(s_mqtt, s_topic, json, 0, 1, 0) < 0) {
            return; /* broker went away again; keep the event */
        }
        event_buffer_pop();
    }
}

/* ------------------------------------------------------------------ mqtt */

static void mqtt_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected");
        s_mqtt_connected = true;
        emit_event("scout_online", "{\"fw\":\"0.1.0\"}");
        flush_buffered();
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected");
        s_mqtt_connected = false;
        break;
    default:
        break;
    }
}

static void mqtt_start(void)
{
    const esp_mqtt_client_config_t cfg = {
        .broker.address.uri = CONFIG_HEXBEE_MQTT_URI,
    };
    s_mqtt = esp_mqtt_client_init(&cfg);
    esp_mqtt_client_register_event(s_mqtt, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(s_mqtt);
}

/* ------------------------------------------------------------------ wifi */

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "Wi-Fi lost, reconnecting");
        esp_wifi_connect();
    } else if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(TAG, "Wi-Fi up");
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_init();
    }
}

static void wifi_start(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               wifi_event_handler, NULL));

    wifi_config_t sta = { 0 };
    strlcpy((char *)sta.sta.ssid, CONFIG_HEXBEE_WIFI_SSID, sizeof(sta.sta.ssid));
    strlcpy((char *)sta.sta.password, CONFIG_HEXBEE_WIFI_PASSWORD,
            sizeof(sta.sta.password));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
    ESP_ERROR_CHECK(esp_wifi_start());
}

/* ------------------------------------------------------------------- app */

static void on_usb_event(usb_watch_event_t evt, const char *detail_json)
{
    emit_event(evt == USB_EVT_INSERTED ? "usb_inserted" : "usb_removed",
               detail_json);
}

static void heartbeat_task(void *arg)
{
    (void)arg;
    int64_t boot = time(NULL);
    char payload[64];
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(CONFIG_HEXBEE_HEARTBEAT_SECONDS * 1000));
        snprintf(payload, sizeof(payload), "{\"uptime_s\":%lld}",
                 (long long)(time(NULL) - boot));
        emit_event("heartbeat", payload);
    }
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    event_buffer_init();
    snprintf(s_topic, sizeof(s_topic), "hexbee/events/%s", CONFIG_HEXBEE_DEVICE_NAME);

    wifi_start();
    mqtt_start();
    usb_watch_start(on_usb_event);

    xTaskCreate(heartbeat_task, "heartbeat", 3072, NULL, tskIDLE_PRIORITY + 1, NULL);
    ESP_LOGI(TAG, "HexBee Scout %s up, publishing to %s",
             CONFIG_HEXBEE_DEVICE_NAME, s_topic);
}
